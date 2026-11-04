import { isCidrSubnetOf, normalizeAuthorizedSenderEntry } from '../shared/ipcidr'
import { t } from '../shared/i18n'
import { isValidSpfTerm } from '../shared/spf-builder'
import type { SpfExpandResult, SpfLookupTreeNode, SpfOptimizationHint } from '../shared/types'
import {
  configureDnsEnvironment,
  resolve4Reliable,
  resolve6Reliable,
  resolveMxReliable,
  resolveTxtReliable
} from './dns-env'

const MAX_DNS_LOOKUPS = 10
const WARN_DNS_LOOKUPS = 8

function flattenTxt(records: string[][]): string[] {
  return records.map((parts) => parts.join(''))
}

/** DNS labels in SPF may include underscores (e.g. _spf.google.com). */
function isDnsName(value: string): boolean {
  return Boolean(value) && /^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$/i.test(value)
}

/** Extract mechanisms/modifiers from a v=spf1 record (exported for tests). */
export function parseSpfTerms(record: string): string[] {
  return record
    .trim()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t && !/^v\s*=\s*spf1$/i.test(t))
}

function stripQualifier(term: string): string {
  return /^[+\-~?]/.test(term) ? term.slice(1) : term
}

/** Normalize ip4:/ip6: mechanism value to a CIDR string. */
export function spfIpMechanismToCidr(kind: 'ip4' | 'ip6', value: string): string | null {
  const raw = value.trim()
  if (!raw) return null
  if (kind === 'ip4') {
    return normalizeAuthorizedSenderEntry(raw.includes('/') ? raw : `${raw}/32`)
  }
  return normalizeAuthorizedSenderEntry(raw.includes('/') ? raw : `${raw}/128`)
}

export type ExpandSpfOptions = {
  /** When set, use this as the root SPF record instead of looking it up via DNS. */
  record?: string | null
  /** Optional DNS resolver overrides for deterministic unit tests. */
  resolvers?: {
    resolveTxt?: (host: string) => Promise<string[][]>
    resolve4?: (host: string) => Promise<string[]>
    resolve6?: (host: string) => Promise<string[]>
    resolveMx?: (host: string) => Promise<Array<{ exchange: string; priority: number }>>
  }
}

function collectSubtreeCidrs(node: SpfLookupTreeNode): string[] {
  const out = new Set<string>(node.cidrs)
  for (const child of node.children) {
    for (const c of collectSubtreeCidrs(child)) out.add(c)
  }
  return [...out]
}

/**
 * Derive actionable optimization hints from an expanded SPF lookup tree.
 */
export function buildSpfOptimizationHints(
  tree: SpfLookupTreeNode,
  totalLookups: number
): SpfOptimizationHint[] {
  const hints: SpfOptimizationHint[] = []
  const seenKeys = new Set<string>()
  const pushHint = (hint: SpfOptimizationHint): void => {
    const key = `${hint.code}|${hint.subject ?? ''}|${hint.related ?? ''}`
    if (seenKeys.has(key)) return
    seenKeys.add(key)
    hints.push(hint)
  }

  if (totalLookups > MAX_DNS_LOOKUPS) {
    pushHint({
      code: 'lookup-limit-exceeded',
      severity: 'error',
      lookups: totalLookups
    })
  } else if (totalLookups >= WARN_DNS_LOOKUPS) {
    pushHint({
      code: 'lookup-budget-high',
      severity: 'warn',
      lookups: totalLookups
    })
  }

  if (tree.record) {
    for (const raw of parseSpfTerms(tree.record)) {
      const lower = raw.toLowerCase()
      if (lower === '+all' || lower === 'all') {
        pushHint({ code: 'all-pass', severity: 'error', subject: raw })
      } else if (lower === '~all') {
        pushHint({ code: 'all-softfail', severity: 'info', subject: raw })
      }
    }
  }

  // Root-level CIDR redundancy and include coverage checks
  const rootIpNodes = tree.children.filter((c) => c.kind === 'ip4' || c.kind === 'ip6')
  const includeBranches = tree.children
    .filter((c) => c.kind === 'include' || c.kind === 'redirect')
    .map((c) => ({ term: c.term, cidrs: collectSubtreeCidrs(c) }))

  for (let i = 0; i < rootIpNodes.length; i++) {
    const nodeA = rootIpNodes[i]!
    const cidrA = nodeA.cidrs[0]
    if (!cidrA) continue

    for (let j = 0; j < rootIpNodes.length; j++) {
      if (i === j) continue
      const nodeB = rootIpNodes[j]!
      const cidrB = nodeB.cidrs[0]
      if (!cidrB) continue
      if (cidrA === cidrB && i > j) {
        pushHint({
          code: 'redundant-cidr',
          severity: 'warn',
          subject: nodeA.term,
          related: nodeB.term
        })
      } else if (cidrA !== cidrB && isCidrSubnetOf(cidrA, cidrB)) {
        pushHint({
          code: 'redundant-cidr',
          severity: 'warn',
          subject: nodeA.term,
          related: nodeB.term
        })
      }
    }

    for (const branch of includeBranches) {
      const covering = branch.cidrs.find((incCidr) => isCidrSubnetOf(cidrA, incCidr))
      if (covering) {
        pushHint({
          code: 'covered-by-include',
          severity: 'info',
          subject: nodeA.term,
          related: `${branch.term} (${covering})`
        })
        break
      }
    }
  }

  const walk = (node: SpfLookupTreeNode, depth: number): void => {
    for (const child of node.children) {
      if (child.kind === 'invalid') {
        pushHint({
          code: 'syntax-error',
          severity: 'error',
          subject: child.term,
          related: node.target ?? undefined
        })
      }
      if (child.kind === 'ptr') {
        pushHint({
          code: 'deprecated-ptr',
          severity: 'warn',
          subject: child.term
        })
      }
      if (child.duplicate && (child.kind === 'include' || child.kind === 'redirect')) {
        pushHint({
          code: depth === 0 ? 'duplicate-include' : 'nested-duplicate-include',
          severity: 'warn',
          subject: child.term,
          related: child.target ?? undefined
        })
      }
      if (child.empty && !child.error && (child.kind === 'a' || child.kind === 'mx')) {
        pushHint({
          code: 'empty-mechanism',
          severity: 'warn',
          subject: child.term
        })
      }
      walk(child, depth + 1)
    }
  }
  walk(tree, 0)

  return hints
}

/**
 * Expand SPF for a domain into concrete IP/CIDR allowlist entries
 * (ip4/ip6/include/a/mx/redirect) and build a lookup tree + optimization hints.
 * Respects the RFC 7208 10 DNS-lookup limit.
 */
export async function expandSpf(
  domainRaw: string,
  options: ExpandSpfOptions = {}
): Promise<SpfExpandResult> {
  configureDnsEnvironment()
  const domain = domainRaw.trim().toLowerCase().replace(/\.$/, '')
  if (!domain || !isDnsName(domain)) {
    throw new Error(t('main.invalidDomain'))
  }

  const txtLookup = options.resolvers?.resolveTxt ?? resolveTxtReliable
  const v4Lookup = options.resolvers?.resolve4 ?? resolve4Reliable
  const v6Lookup = options.resolvers?.resolve6 ?? resolve6Reliable
  const mxLookup = options.resolvers?.resolveMx ?? resolveMxReliable

  const resolveHost = async (host: string): Promise<string[]> => {
    const out: string[] = []
    try {
      const v4 = await v4Lookup(host)
      for (const ip of v4) {
        const cidr = normalizeAuthorizedSenderEntry(ip)
        if (cidr) out.push(cidr)
      }
    } catch {
      // no A records
    }
    try {
      const v6 = await v6Lookup(host)
      for (const ip of v6) {
        const cidr = normalizeAuthorizedSenderEntry(ip)
        if (cidr) out.push(cidr)
      }
    } catch {
      // no AAAA records
    }
    return out
  }

  const overrideRoot = options.record?.trim() || null
  const cidrs = new Set<string>()
  const errors: string[] = []
  const visited = new Set<string>()
  const activeStack = new Set<string>()
  let lookups = 0
  let rootRecord: string | null = null

  const addCidr = (cidr: string | null): void => {
    if (cidr) cidrs.add(cidr)
  }

  async function processDomain(
    name: string,
    isRoot: boolean,
    termLabel: string,
    nodeKind: 'root' | 'include' | 'redirect'
  ): Promise<SpfLookupTreeNode> {
    const key = name.toLowerCase().replace(/\.$/, '')
    const node: SpfLookupTreeNode = {
      kind: nodeKind,
      term: termLabel,
      target: key || null,
      record: null,
      ownLookups: 0,
      totalLookups: 0,
      cidrs: [],
      children: []
    }
    if (!key) return node

    if (activeStack.has(key)) {
      node.cycle = true
      node.duplicate = true
      node.error = `Recursive SPF loop at ${key}`
      errors.push(node.error)
      return node
    }

    const alreadyVisited = visited.has(key)
    visited.add(key)

    let record: string | null = null
    if (isRoot && overrideRoot) {
      record = overrideRoot
    } else {
      if (lookups >= MAX_DNS_LOOKUPS) {
        const err = `DNS lookup limit (${MAX_DNS_LOOKUPS}) reached at ${key}`
        node.error = err
        errors.push(err)
        return node
      }
      lookups++
      node.ownLookups = 1
      node.totalLookups = 1
      if (alreadyVisited) {
        node.duplicate = true
        return node
      }
      try {
        const txt = flattenTxt(await txtLookup(key))
        record = txt.find((r) => /v\s*=\s*spf1/i.test(r)) ?? null
      } catch (err) {
        const msg = `${key}: ${err instanceof Error ? err.message : String(err)}`
        node.error = msg
        errors.push(msg)
        return node
      }
    }

    if (!record) {
      const msg = `${key}: no SPF record`
      node.error = msg
      errors.push(msg)
      return node
    }
    node.record = record
    if (isRoot) rootRecord = record

    activeStack.add(key)
    try {
      let redirect: string | null = null
      let redirectRawTerm = ''
      for (const rawTerm of parseSpfTerms(record)) {
        if (!isValidSpfTerm(rawTerm)) {
          const msg = `${key}: invalid SPF mechanism "${rawTerm}" (RFC 7208 PermError)`
          errors.push(msg)
          node.children.push({
            kind: 'invalid',
            term: rawTerm,
            target: null,
            record: null,
            ownLookups: 0,
            totalLookups: 0,
            cidrs: [],
            error: msg,
            children: []
          })
          continue
        }
        const term = stripQualifier(rawTerm)
        const lower = term.toLowerCase()

        if (lower === 'all' || lower.startsWith('exp=')) continue

        if (lower.startsWith('exists:')) {
          const target = term.slice('exists:'.length).trim().toLowerCase()
          const existsNode: SpfLookupTreeNode = {
            kind: 'exists',
            term: rawTerm,
            target: target || null,
            record: null,
            ownLookups: 0,
            totalLookups: 0,
            cidrs: [],
            children: []
          }
          if (lookups >= MAX_DNS_LOOKUPS) {
            const msg = `DNS lookup limit reached before ${rawTerm}`
            existsNode.error = msg
            errors.push(msg)
          } else {
            lookups++
            existsNode.ownLookups = 1
            existsNode.totalLookups = 1
          }
          node.children.push(existsNode)
          continue
        }

        if (lower === 'ptr' || lower.startsWith('ptr:')) {
          const target = lower.startsWith('ptr:') ? term.slice(4).trim().toLowerCase() : key
          const ptrNode: SpfLookupTreeNode = {
            kind: 'ptr',
            term: rawTerm,
            target: target || key,
            record: null,
            ownLookups: 0,
            totalLookups: 0,
            cidrs: [],
            children: []
          }
          if (lookups >= MAX_DNS_LOOKUPS) {
            const msg = `DNS lookup limit reached before ${rawTerm}`
            ptrNode.error = msg
            errors.push(msg)
          } else {
            lookups++
            ptrNode.ownLookups = 1
            ptrNode.totalLookups = 1
          }
          node.children.push(ptrNode)
          continue
        }

        if (lower.startsWith('redirect=')) {
          redirect = term.slice('redirect='.length).trim().toLowerCase()
          redirectRawTerm = rawTerm
          continue
        }

        if (lower.startsWith('ip4:')) {
          const cidr = spfIpMechanismToCidr('ip4', term.slice(4))
          addCidr(cidr)
          if (cidr) {
            node.cidrs.push(cidr)
            node.children.push({
              kind: 'ip4',
              term: rawTerm,
              target: cidr,
              record: null,
              ownLookups: 0,
              totalLookups: 0,
              cidrs: [cidr],
              children: []
            })
          }
          continue
        }
        if (lower.startsWith('ip6:')) {
          const cidr = spfIpMechanismToCidr('ip6', term.slice(4))
          addCidr(cidr)
          if (cidr) {
            node.cidrs.push(cidr)
            node.children.push({
              kind: 'ip6',
              term: rawTerm,
              target: cidr,
              record: null,
              ownLookups: 0,
              totalLookups: 0,
              cidrs: [cidr],
              children: []
            })
          }
          continue
        }

        if (lower.startsWith('include:')) {
          const inc = term.slice('include:'.length).trim().toLowerCase()
          if (isDnsName(inc)) {
            const child = await processDomain(inc, false, rawTerm, 'include')
            node.children.push(child)
          }
          continue
        }

        if (lower === 'a' || lower.startsWith('a:') || lower.startsWith('a/')) {
          const host =
            lower === 'a' || lower.startsWith('a/')
              ? key
              : term.slice(2).replace(/^\//, '').split('/')[0]?.trim() || key
          const aNode: SpfLookupTreeNode = {
            kind: 'a',
            term: rawTerm,
            target: host,
            record: null,
            ownLookups: 0,
            totalLookups: 0,
            cidrs: [],
            children: []
          }
          if (lookups >= MAX_DNS_LOOKUPS) {
            const msg = `DNS lookup limit reached before a:${key}`
            aNode.error = msg
            errors.push(msg)
            node.children.push(aNode)
            continue
          }
          lookups++
          aNode.ownLookups = 1
          aNode.totalLookups = 1
          const resolved = await resolveHost(host)
          for (const c of resolved) {
            addCidr(c)
            aNode.cidrs.push(c)
          }
          if (resolved.length === 0) aNode.empty = true
          node.children.push(aNode)
          continue
        }

        if (lower === 'mx' || lower.startsWith('mx:') || lower.startsWith('mx/')) {
          const host =
            lower === 'mx' || lower.startsWith('mx/')
              ? key
              : term.slice(3).replace(/^\//, '').split('/')[0]?.trim() || key
          const mxNode: SpfLookupTreeNode = {
            kind: 'mx',
            term: rawTerm,
            target: host,
            record: null,
            ownLookups: 0,
            totalLookups: 0,
            cidrs: [],
            children: []
          }
          if (lookups >= MAX_DNS_LOOKUPS) {
            const msg = `DNS lookup limit reached before mx:${key}`
            mxNode.error = msg
            errors.push(msg)
            node.children.push(mxNode)
            continue
          }
          lookups++
          mxNode.ownLookups = 1
          try {
            const mxs = await mxLookup(host)
            for (const mx of mxs.slice(0, 10)) {
              for (const c of await resolveHost(mx.exchange)) {
                addCidr(c)
                mxNode.cidrs.push(c)
              }
            }
            if (mxNode.cidrs.length === 0) mxNode.empty = true
          } catch (err) {
            const msg = `mx ${host}: ${err instanceof Error ? err.message : String(err)}`
            mxNode.error = msg
            errors.push(msg)
          }
          mxNode.totalLookups = mxNode.ownLookups
          node.children.push(mxNode)
        }
      }

      if (redirect && isDnsName(redirect)) {
        const child = await processDomain(
          redirect,
          false,
          redirectRawTerm || `redirect=${redirect}`,
          'redirect'
        )
        node.children.push(child)
      }
    } finally {
      activeStack.delete(key)
    }

    node.totalLookups =
      node.ownLookups + node.children.reduce((sum, child) => sum + child.totalLookups, 0)
    return node
  }

  const tree = await processDomain(domain, true, domain, 'root')
  const hints = buildSpfOptimizationHints(tree, lookups)

  return {
    domain,
    record: rootRecord,
    cidrs: [...cidrs].sort(),
    lookups,
    errors,
    tree,
    hints
  }
}
