import { categorizeFailure, isHealthyDmarcOutcome } from './analyze'
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
import type { DnsCheckResult, FailCategory, FailCategoryCounts, ReportRow } from './types'

/** Reports older than this add little to a rollout decision. */
export const ROLLOUT_WINDOW_DAYS = 30
/** Below this volume a percentage says nothing about the next step. */
export const ROLLOUT_MIN_MESSAGES = 100

export type RolloutStageId =
  'monitor' | 'quarantinePartial' | 'quarantineFull' | 'rejectPartial' | 'rejectFull'

interface StageDef {
  id: RolloutStageId
  policy: DmarcPolicy
  pct: number
  /** Days of observation recommended before entering this stage. */
  minDays: number
  /** Highest share (%) of legitimate-looking fails that may still be delivered. */
  maxRiskRate: number
}

/**
 * The usual DMARC ladder. Each rung tightens either the policy or its coverage,
 * never both at once, so a surprise stays traceable to a single change.
 */
const LADDER: StageDef[] = [
  { id: 'monitor', policy: 'none', pct: 100, minDays: 0, maxRiskRate: Number.POSITIVE_INFINITY },
  { id: 'quarantinePartial', policy: 'quarantine', pct: 25, minDays: 14, maxRiskRate: 5 },
  { id: 'quarantineFull', policy: 'quarantine', pct: 100, minDays: 14, maxRiskRate: 2 },
  { id: 'rejectPartial', policy: 'reject', pct: 25, minDays: 14, maxRiskRate: 1 },
  { id: 'rejectFull', policy: 'reject', pct: 100, minDays: 14, maxRiskRate: 0.5 }
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

export interface RolloutCurrentPolicy {
  found: boolean
  policy: DmarcPolicy | null
  pct: number
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
  pct: number
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
  return {
    found: Boolean(dns?.dmarc.found),
    policy: dns?.dmarc.found ? (parsed.policy ?? 'none') : null,
    pct: normalizePct(parsed.pct ?? 100),
    rua: parsed.rua ?? '',
    spfOk: dns ? dns.spf.found : null,
    dkimOk: !dns || selectors.length === 0 ? null : selectors.every((s) => s.found)
  }
}

function stageIndexFor(policy: DmarcPolicy | null, pct: number): number {
  if (!policy) return -1
  if (policy === 'none') return 0
  const full = pct >= 100
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
): { metrics: RolloutMetrics; riskSources: RolloutRiskSource[] } {
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
    riskSources
  }
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

/** Base record fields: keep the published alignment/reporting tags, only policy moves. */
function baseInput(
  domain: string,
  current: RolloutCurrentPolicy,
  record: string
): DmarcBuilderInput {
  return {
    ...DEFAULT_BUILDER_INPUT,
    ...(record ? parseDmarcRecord(record) : {}),
    domain,
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
  const { metrics, riskSources } = collectMetrics(domain, reports, windowDays)
  const current = readCurrentPolicy(input.dns)

  const currentIndex = stageIndexFor(current.policy, current.pct)
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
    const built = buildDmarcRecord({ ...base, policy: stage.policy, pct: stage.pct })
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
      pct: stage.pct,
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
    plan
  }
}
