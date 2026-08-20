import { categorizeFailure, isHealthyDmarcOutcome } from './analyze'
import { isRelaxedAligned, normalizeHost, organizationalDomain } from './domain'
import {
  buildDmarcRecord,
  DEFAULT_BUILDER_INPUT,
  defaultDmarcMailbox,
  normalizeDomain,
  normalizePct,
  parseDmarcRecord,
  type DmarcBuilderInput,
  type DmarcPolicy
} from './dmarc-builder'
import type {
  DnsCheckResult,
  FailCategory,
  FailCategoryCounts,
  ReportRow,
  SerializedRecord
} from './types'

/** Reports older than this add little to a rollout decision. */
export const ROLLOUT_WINDOW_DAYS = 30
/** Below this volume a percentage says nothing about the next step. */
export const ROLLOUT_MIN_MESSAGES = 100

export type RolloutStageId =
  'monitor' | 'quarantinePartial' | 'quarantineFull' | 'rejectPartial' | 'rejectFull'

interface StageDef {
  id: RolloutStageId
  policy: DmarcPolicy
  /** `t=y` (RFC 9989): ask receivers to keep delivering failing mail while testing this rung. */
  testing: boolean
  /** Days of observation recommended before entering this stage. */
  minDays: number
  /** Highest share (%) of legitimate-looking fails that may still be delivered. */
  maxRiskRate: number
}

/**
 * The usual DMARC ladder. Each rung tightens either the policy or its testing flag,
 * never both at once, so a surprise stays traceable to a single change.
 * RFC 9989 deprecated `pct=` for staged rollouts in favor of `t=y` (testing mode).
 */
const LADDER: StageDef[] = [
  {
    id: 'monitor',
    policy: 'none',
    testing: false,
    minDays: 0,
    maxRiskRate: Number.POSITIVE_INFINITY
  },
  { id: 'quarantinePartial', policy: 'quarantine', testing: true, minDays: 14, maxRiskRate: 5 },
  { id: 'quarantineFull', policy: 'quarantine', testing: false, minDays: 14, maxRiskRate: 2 },
  { id: 'rejectPartial', policy: 'reject', testing: true, minDays: 14, maxRiskRate: 1 },
  { id: 'rejectFull', policy: 'reject', testing: false, minDays: 14, maxRiskRate: 0.5 }
]

export interface RolloutMetrics {
  domain: string
  windowDays: number
  reportCount: number
  reportingOrgs: number
  messages: number
  healthy: number
  /** Share (%) of messages with a healthy DMARC outcome. */
  healthRate: number
  /** Delivered fails from senders that look legitimate — these break on a stricter policy. */
  risk: number
  riskRate: number
  /** Delivered fails without any authenticated domain — a stricter policy should stop these. */
  spoof: number
  riskByCategory: FailCategoryCounts
  riskSourceCount: number
  daysObserved: number
  firstSeen: string | null
  lastSeen: string | null
}

export interface RolloutRiskSource {
  sourceIp: string
  count: number
  category: FailCategory
  headerFrom: string | null
}

export type RolloutWhatIfScenarioId = 'reject' | 'strictDkim' | 'subdomainReject'
export type RolloutSimulationMode = 'off' | RolloutWhatIfScenarioId

export interface RolloutWhatIfAffectedSource extends RolloutRiskSource {
  shareRate: number
}

export interface RolloutWhatIfFixPlan {
  sourceCount: number
  messageCount: number
  riskRateAfter: number
}

export interface RolloutWhatIfScenario {
  id: RolloutWhatIfScenarioId
  affected: number
  affectedRate: number
  affectedSources: RolloutWhatIfAffectedSource[]
  fixPlan: RolloutWhatIfFixPlan | null
}

export interface RolloutCurrentPolicy {
  found: boolean
  policy: DmarcPolicy | null
  /** @deprecated Historical per RFC 9989; kept only to recognize older records already on a partial rollout. */
  pct: number
  /** `t=y` on the published record, or a legacy `pct<100` treated as equivalent. */
  testing: boolean
  rua: string
  spfOk: boolean | null
  dkimOk: boolean | null
}

export type RolloutBlockerKey =
  | 'dnsPending'
  | 'noRecord'
  | 'noRua'
  | 'noData'
  | 'lowVolume'
  | 'shortWindow'
  | 'highRisk'
  | 'noSpf'
  | 'dkimMissing'

export interface RolloutBlocker {
  key: RolloutBlockerKey
  actual?: number
  limit?: number
}

export type RolloutStepState = 'done' | 'current' | 'next' | 'later'

export interface RolloutStep {
  id: RolloutStageId
  policy: DmarcPolicy
  testing: boolean
  minDays: number
  maxRiskRate: number
  host: string
  record: string
  state: RolloutStepState
}

export interface RolloutAssessment {
  metrics: RolloutMetrics
  current: RolloutCurrentPolicy
  currentStage: RolloutStageId | null
  nextStage: RolloutStageId | null
  /** True when the next rung can be taken now. */
  ready: boolean
  blockers: RolloutBlocker[]
  riskSources: RolloutRiskSource[]
  whatIf: RolloutWhatIfScenario[]
  plan: RolloutStep[]
}

export interface RolloutInput {
  domain: string
  reports: ReportRow[]
  dns?: DnsCheckResult | null
  now?: Date
  windowDays?: number
}

/** Current policy from a DNS check; `found: false` means DMARC is not published yet. */
export function readCurrentPolicy(dns: DnsCheckResult | null | undefined): RolloutCurrentPolicy {
  const record = dns?.dmarc.records?.[0] ?? ''
  const parsed = record ? parseDmarcRecord(record) : {}
  const selectors = dns?.dkim.selectors ?? []
  const pct = normalizePct(parsed.pct ?? 100)
  return {
    found: Boolean(dns?.dmarc.found),
    policy: dns?.dmarc.found ? (parsed.policy ?? 'none') : null,
    pct,
    // A legacy pct<100 record is on a partial rollout even without t=y.
    testing: Boolean(parsed.testing) || pct < 100,
    rua: parsed.rua ?? '',
    spfOk: dns ? dns.spf.found : null,
    dkimOk: !dns || selectors.length === 0 ? null : selectors.every((s) => s.found)
  }
}

function stageIndexFor(policy: DmarcPolicy | null, testing: boolean): number {
  if (!policy) return -1
  if (policy === 'none') return 0
  const full = !testing
  if (policy === 'quarantine') return full ? 2 : 1
  return full ? 4 : 3
}

function dayDiff(from: string | null, to: string | null): number {
  if (!from || !to) return 0
  const start = new Date(from).getTime()
  const end = new Date(to).getTime()
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return 0
  return Math.round((end - start) / 86_400_000)
}

function collectMetrics(
  domain: string,
  reports: ReportRow[],
  windowDays: number
): { metrics: RolloutMetrics; riskSources: RolloutRiskSource[]; whatIf: RolloutWhatIfScenario[] } {
  type SourceAcc = {
    count: number
    categories: FailCategoryCounts
    fromCounts: Map<string, number>
  }
  const sources = new Map<string, SourceAcc>()
  const orgs = new Set<string>()
  const riskByCategory: FailCategoryCounts = {}
  let messages = 0
  let healthy = 0
  let risk = 0
  let spoof = 0
  let firstSeen: string | null = null
  let lastSeen: string | null = null

  for (const report of reports) {
    orgs.add((report.orgName || '').trim().toLowerCase())
    if (!firstSeen || report.dateBegin < firstSeen) firstSeen = report.dateBegin
    if (!lastSeen || report.dateEnd > lastSeen) lastSeen = report.dateEnd
    for (const rec of report.records) {
      const n = rec.count || 0
      messages += n
      if (isHealthyDmarcOutcome(rec)) {
        healthy += n
        continue
      }
      const category = categorizeFailure(rec, report.domain)
      if (category === 'unauthenticated') {
        spoof += n
        continue
      }
      risk += n
      riskByCategory[category] = (riskByCategory[category] ?? 0) + n
      const ip = (rec.sourceIp || '').trim() || '—'
      const acc = sources.get(ip) ?? { count: 0, categories: {}, fromCounts: new Map() }
      acc.count += n
      acc.categories[category] = (acc.categories[category] ?? 0) + n
      const from = (rec.headerFrom || '').trim()
      if (from) acc.fromCounts.set(from, (acc.fromCounts.get(from) ?? 0) + n)
      sources.set(ip, acc)
    }
  }

  const riskSources: RolloutRiskSource[] = [...sources.entries()]
    .map(([sourceIp, acc]) => {
      let category: FailCategory = 'broken'
      let best = 0
      for (const [cat, count] of Object.entries(acc.categories) as Array<[FailCategory, number]>) {
        if (count > best) {
          best = count
          category = cat
        }
      }
      let headerFrom: string | null = null
      let bestFrom = 0
      for (const [from, count] of acc.fromCounts) {
        if (count > bestFrom) {
          bestFrom = count
          headerFrom = from
        }
      }
      return { sourceIp, count: acc.count, category, headerFrom }
    })
    .sort((a, b) => b.count - a.count)

  return {
    metrics: {
      domain,
      windowDays,
      reportCount: reports.length,
      reportingOrgs: [...orgs].filter(Boolean).length,
      messages,
      healthy,
      healthRate: messages ? Math.round((healthy / messages) * 1000) / 10 : 100,
      risk,
      riskRate: messages ? Math.round((risk / messages) * 10_000) / 100 : 0,
      spoof,
      riskByCategory,
      riskSourceCount: riskSources.length,
      daysObserved: dayDiff(firstSeen, lastSeen),
      firstSeen,
      lastSeen
    },
    riskSources,
    whatIf: buildWhatIfScenarios(domain, reports, messages)
  }
}

type WhatIfSourceAcc = {
  count: number
  categories: FailCategoryCounts
  fromCounts: Map<string, number>
}

function isStrictAligned(
  authDomain: string | null | undefined,
  fromDomain: string | null
): boolean {
  const auth = normalizeHost(authDomain)
  const from = normalizeHost(fromDomain)
  return Boolean(auth && from && auth === from)
}

function isSubdomainOf(domain: string | null | undefined, orgDomain: string): boolean {
  const host = normalizeHost(domain)
  return Boolean(host && host !== orgDomain && organizationalDomain(host) === orgDomain)
}

function wouldFailStrictDkim(rec: SerializedRecord, policyDomain: string): boolean {
  if (!rec.passesDmarc) return false
  const from = rec.headerFrom || policyDomain
  const dkimPass = (rec.dkimResult ?? '').toLowerCase() === 'pass'
  const spfPass = (rec.spfResult ?? '').toLowerCase() === 'pass'
  const strictDkimPass = dkimPass && isStrictAligned(rec.dkimDomain, from)
  const relaxedSpfPass = spfPass && isRelaxedAligned(rec.spfDomain, from)
  return !strictDkimPass && !relaxedSpfPass
}

function wouldFailSubdomainReject(rec: SerializedRecord, domain: string): boolean {
  if (!isSubdomainOf(rec.headerFrom, domain)) return false
  if (isHealthyDmarcOutcome(rec)) return false
  return categorizeFailure(rec, domain) !== 'unauthenticated'
}

function addWhatIfSource(
  sources: Map<string, WhatIfSourceAcc>,
  rec: SerializedRecord,
  policyDomain: string,
  count: number
): void {
  const ip = (rec.sourceIp || '').trim() || '—'
  const acc = sources.get(ip) ?? { count: 0, categories: {}, fromCounts: new Map() }
  const category = categorizeFailure(rec, policyDomain)
  acc.count += count
  acc.categories[category] = (acc.categories[category] ?? 0) + count
  const from = (rec.headerFrom || '').trim()
  if (from) acc.fromCounts.set(from, (acc.fromCounts.get(from) ?? 0) + count)
  sources.set(ip, acc)
}

function whatIfSources(
  sources: Map<string, WhatIfSourceAcc>,
  messages: number
): RolloutWhatIfAffectedSource[] {
  return [...sources.entries()]
    .map(([sourceIp, acc]) => {
      let category: FailCategory = 'broken'
      let best = 0
      for (const [cat, count] of Object.entries(acc.categories) as Array<[FailCategory, number]>) {
        if (count > best) {
          best = count
          category = cat
        }
      }
      let headerFrom: string | null = null
      let bestFrom = 0
      for (const [from, count] of acc.fromCounts) {
        if (count > bestFrom) {
          bestFrom = count
          headerFrom = from
        }
      }
      return {
        sourceIp,
        count: acc.count,
        category,
        headerFrom,
        shareRate: messages ? Math.round((acc.count / messages) * 10_000) / 100 : 0
      }
    })
    .sort((a, b) => b.count - a.count)
}

function buildFixPlan(
  affected: number,
  sources: RolloutWhatIfAffectedSource[],
  messages: number
): RolloutWhatIfFixPlan | null {
  if (affected <= 0 || sources.length === 0) return null
  const fixed = sources.slice(0, 3)
  const fixedMessages = fixed.reduce((sum, source) => sum + source.count, 0)
  const remaining = Math.max(0, affected - fixedMessages)
  return {
    sourceCount: fixed.length,
    messageCount: fixedMessages,
    riskRateAfter: messages ? Math.round((remaining / messages) * 10_000) / 100 : 0
  }
}

function scenario(
  id: RolloutWhatIfScenarioId,
  affected: number,
  sources: Map<string, WhatIfSourceAcc>,
  messages: number
): RolloutWhatIfScenario {
  const affectedSources = whatIfSources(sources, messages)
  return {
    id,
    affected,
    affectedRate: messages ? Math.round((affected / messages) * 10_000) / 100 : 0,
    affectedSources: affectedSources.slice(0, 4),
    fixPlan: buildFixPlan(affected, affectedSources, messages)
  }
}

function buildWhatIfScenarios(
  domain: string,
  reports: ReportRow[],
  messages: number
): RolloutWhatIfScenario[] {
  const rejectSources = new Map<string, WhatIfSourceAcc>()
  const strictDkimSources = new Map<string, WhatIfSourceAcc>()
  const subdomainSources = new Map<string, WhatIfSourceAcc>()
  let reject = 0
  let strictDkim = 0
  let subdomainReject = 0

  for (const report of reports) {
    for (const rec of report.records) {
      const count = rec.count || 0
      if (count <= 0) continue
      const category = categorizeFailure(rec, report.domain)
      if (!isHealthyDmarcOutcome(rec) && category !== 'unauthenticated') {
        reject += count
        addWhatIfSource(rejectSources, rec, report.domain, count)
      }
      if (wouldFailStrictDkim(rec, report.domain)) {
        strictDkim += count
        addWhatIfSource(strictDkimSources, rec, report.domain, count)
      }
      if (wouldFailSubdomainReject(rec, domain)) {
        subdomainReject += count
        addWhatIfSource(subdomainSources, rec, report.domain, count)
      }
    }
  }

  return [
    scenario('reject', reject, rejectSources, messages),
    scenario('strictDkim', strictDkim, strictDkimSources, messages),
    scenario('subdomainReject', subdomainReject, subdomainSources, messages)
  ]
}

function simulatedRecord(
  rec: SerializedRecord,
  reportDomain: string,
  targetDomain: string,
  mode: RolloutSimulationMode
): SerializedRecord {
  if (mode === 'off') return rec
  if (mode === 'reject') {
    const category = categorizeFailure(rec, reportDomain)
    if (!isHealthyDmarcOutcome(rec) && category !== 'unauthenticated') {
      return { ...rec, disposition: 'reject' }
    }
    return rec
  }
  if (mode === 'strictDkim') {
    if (!wouldFailStrictDkim(rec, reportDomain)) return rec
    return {
      ...rec,
      passesDmarc: false,
      disposition: 'none',
      dkimResult: 'fail',
      reasons: [
        ...(rec.reasons ?? []),
        { type: 'simulated_policy', comment: 'strict DKIM alignment' }
      ]
    }
  }
  if (mode === 'subdomainReject' && wouldFailSubdomainReject(rec, targetDomain)) {
    return { ...rec, disposition: 'reject' }
  }
  return rec
}

function reportWithSimulatedRecords(report: ReportRow, records: SerializedRecord[]): ReportRow {
  let total = 0
  let passing = 0
  for (const rec of records) {
    total += rec.count || 0
    if (rec.passesDmarc) passing += rec.count || 0
  }
  return {
    ...report,
    records,
    total,
    passing,
    failing: total - passing,
    passRate: total ? Math.round((passing / total) * 1000) / 10 : 0
  }
}

export function simulateRolloutReports(
  reports: ReportRow[],
  domainRaw: string,
  mode: RolloutSimulationMode
): ReportRow[] {
  const domain = normalizeDomain(domainRaw)
  if (!domain || mode === 'off') return reports
  return reports.map((report) => {
    const applies = mode === 'subdomainReject' || normalizeDomain(report.domain || '') === domain
    if (!applies) return report
    let changed = false
    const records = report.records.map((rec) => {
      const next = simulatedRecord(rec, report.domain, domain, mode)
      if (next !== rec) changed = true
      return next
    })
    return changed ? reportWithSimulatedRecords(report, records) : report
  })
}

/** Reports of one domain inside the rollout window, newest window first. */
export function reportsForRollout(
  reports: ReportRow[],
  domain: string,
  options: { now?: Date; windowDays?: number } = {}
): ReportRow[] {
  const target = normalizeDomain(domain)
  const windowDays = options.windowDays ?? ROLLOUT_WINDOW_DAYS
  const cutoff = (options.now ?? new Date()).getTime() - windowDays * 86_400_000
  return reports.filter((r) => {
    if (normalizeDomain(r.domain || '') !== target) return false
    const end = new Date(r.dateEnd).getTime()
    return Number.isFinite(end) ? end >= cutoff : true
  })
}

/** Base record fields: keep the published alignment/reporting tags, only policy/testing move. */
function baseInput(
  domain: string,
  current: RolloutCurrentPolicy,
  record: string
): DmarcBuilderInput {
  return {
    ...DEFAULT_BUILDER_INPUT,
    ...(record ? parseDmarcRecord(record) : {}),
    domain,
    // The ladder drives partial rollout via t=y now; drop any legacy pct< 100 carried over.
    pct: 100,
    rua: current.rua || defaultDmarcMailbox(domain)
  }
}

/**
 * Recommend the next DMARC rung for one domain and lay out the remaining plan.
 * The decision rests on delivered fails from senders that still look legitimate:
 * those are the messages a stricter policy would lose.
 */
export function assessRollout(input: RolloutInput): RolloutAssessment {
  const domain = normalizeDomain(input.domain)
  const windowDays = input.windowDays ?? ROLLOUT_WINDOW_DAYS
  const reports = reportsForRollout(input.reports, domain, { now: input.now, windowDays })
  const { metrics, riskSources, whatIf } = collectMetrics(domain, reports, windowDays)
  const current = readCurrentPolicy(input.dns)

  const currentIndex = stageIndexFor(current.policy, current.testing)
  const nextIndex = Math.min(currentIndex + 1, LADDER.length - 1)
  const next = currentIndex < LADDER.length - 1 ? LADDER[nextIndex] : null

  // Publishing p=none is always safe, so only the stricter rungs carry conditions.
  const blockers: RolloutBlocker[] = []
  if (!input.dns) {
    blockers.push({ key: 'dnsPending' })
  } else if (next && next.policy !== 'none') {
    if (!current.found) blockers.push({ key: 'noRecord' })
    else if (!current.rua) blockers.push({ key: 'noRua' })
    if (current.spfOk === false) blockers.push({ key: 'noSpf' })
    if (current.dkimOk === false) blockers.push({ key: 'dkimMissing' })
    if (metrics.messages === 0) {
      blockers.push({ key: 'noData' })
    } else if (metrics.messages < ROLLOUT_MIN_MESSAGES) {
      blockers.push({ key: 'lowVolume', actual: metrics.messages, limit: ROLLOUT_MIN_MESSAGES })
    }
    if (metrics.messages > 0 && metrics.daysObserved < next.minDays) {
      blockers.push({ key: 'shortWindow', actual: metrics.daysObserved, limit: next.minDays })
    }
    if (metrics.messages > 0 && metrics.riskRate > next.maxRiskRate) {
      blockers.push({ key: 'highRisk', actual: metrics.riskRate, limit: next.maxRiskRate })
    }
  }

  const record = input.dns?.dmarc.records?.[0] ?? ''
  const base = baseInput(domain, current, record)
  const plan: RolloutStep[] = LADDER.map((stage, index) => {
    const built = buildDmarcRecord({ ...base, policy: stage.policy, testing: stage.testing })
    const state: RolloutStepState =
      index < currentIndex
        ? 'done'
        : index === currentIndex
          ? 'current'
          : index === nextIndex && next
            ? 'next'
            : 'later'
    return {
      id: stage.id,
      policy: stage.policy,
      testing: stage.testing,
      minDays: stage.minDays,
      maxRiskRate: stage.maxRiskRate,
      host: built.host,
      record: built.value,
      state
    }
  })

  return {
    metrics,
    current,
    currentStage: currentIndex >= 0 ? LADDER[currentIndex].id : null,
    nextStage: next?.id ?? null,
    ready: Boolean(next) && blockers.length === 0,
    blockers,
    riskSources: riskSources.slice(0, 8),
    whatIf,
    plan
  }
}
