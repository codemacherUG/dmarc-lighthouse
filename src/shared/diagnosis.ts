/**
 * "Why did this fail?" — turns the failure category, plus the raw (unaligned)
 * SPF/DKIM auth_results and the identified sending service, into a structured
 * verdict and a concrete next step. No AI involved: sender classification,
 * alignment and the aggregate-report data already carry the answer.
 */
import { isRelaxedAligned } from './domain'
import { categorizeFailure } from './analyze'
import type { FailCategory, SenderKind, SerializedRecord } from './types'

export type DiagnosisVerdict = 'likelyLegit' | 'possiblyLegit' | 'suspicious' | 'forwarded'

export type DiagnosisAction =
  | 'checkDkimSigning'
  | 'checkSpfAlignment'
  | 'fixSpfAuth'
  | 'fixDkimAuth'
  | 'addSenderToSpf'
  | 'reviewForwarder'
  | 'investigateSpoof'
  | 'noAction'

/** Raw (unaligned) auth_results facts for one mechanism, plus its alignment. */
export interface AuthMechanismFacts {
  /** Domain the mechanism authenticated (auth_results), if any. */
  domain: string | null
  /** Raw pass/fail from auth_results, when known ("pass" | "fail" | "none" | ...). */
  raw: string | null
  /** Whether `domain` aligns (relaxed) with the header-from domain. */
  aligned: boolean
}

export interface FailureDiagnosis {
  verdict: DiagnosisVerdict
  category: FailCategory
  action: DiagnosisAction
  /** Dominant RFC5322.From domain this diagnosis is about. */
  domain: string
  senderName: string | null
  senderKind: SenderKind | null
  spf: AuthMechanismFacts
  dkim: AuthMechanismFacts
  /** Message count the diagnosis is based on. */
  sampleCount: number
}

function pickDominant<T>(counts: Map<T, number>): T | null {
  let best: T | null = null
  let bestCount = -1
  for (const [key, count] of counts) {
    if (count > bestCount) {
      bestCount = count
      best = key
    }
  }
  return best
}

function mechanismFacts(
  records: SerializedRecord[],
  from: string,
  domainKey: 'spfDomain' | 'dkimDomain',
  rawKey: 'spfRawResult' | 'dkimRawResult'
): AuthMechanismFacts {
  const domainCounts = new Map<string | null, number>()
  const rawCounts = new Map<string | null, number>()
  for (const rec of records) {
    const domain = rec[domainKey]
    if (domain) domainCounts.set(domain, (domainCounts.get(domain) ?? 0) + rec.count)
    if (domain)
      rawCounts.set(rec[rawKey] ?? null, (rawCounts.get(rec[rawKey] ?? null) ?? 0) + rec.count)
  }
  const domain = pickDominant(domainCounts)
  const raw = domain ? pickDominant(rawCounts) : null
  return { domain, raw, aligned: Boolean(domain) && isRelaxedAligned(domain, from) }
}

/**
 * Diagnose why a set of aggregate-report records for one problem source keep
 * failing DMARC. `records` should be the already-filtered rows for a single
 * source-IP group (all delivered, non-passing outcomes).
 */
export function diagnoseSource(
  records: SerializedRecord[],
  policyDomain: string,
  sender?: { name: string | null; kind: SenderKind | null } | null,
  isOwnAuthorizedSender = false
): FailureDiagnosis | null {
  if (!records.length) return null

  const fromCounts = new Map<string, number>()
  const categoryCounts = new Map<FailCategory, number>()
  let sampleCount = 0
  for (const rec of records) {
    sampleCount += rec.count
    const from = rec.headerFrom || policyDomain
    fromCounts.set(from, (fromCounts.get(from) ?? 0) + rec.count)
    const category = categorizeFailure(rec, policyDomain)
    categoryCounts.set(category, (categoryCounts.get(category) ?? 0) + rec.count)
  }
  const from = pickDominant(fromCounts) ?? policyDomain
  const category = pickDominant(categoryCounts) ?? 'unauthenticated'
  const relevant = records.filter((rec) => (rec.headerFrom || policyDomain) === from)

  const spf = mechanismFacts(relevant, from, 'spfDomain', 'spfRawResult')
  const dkim = mechanismFacts(relevant, from, 'dkimDomain', 'dkimRawResult')

  let verdict: DiagnosisVerdict
  let action: DiagnosisAction

  if (category === 'forwarder') {
    verdict = 'forwarded'
    action = 'reviewForwarder'
  } else if (category === 'unauthenticated') {
    verdict = isOwnAuthorizedSender ? 'possiblyLegit' : 'suspicious'
    action = isOwnAuthorizedSender ? 'checkDkimSigning' : 'investigateSpoof'
  } else if (category === 'thirdParty') {
    verdict = isOwnAuthorizedSender ? 'likelyLegit' : 'possiblyLegit'
    if (!dkim.domain) action = 'checkDkimSigning'
    else if (spf.raw === 'pass' || dkim.raw === 'pass') action = 'checkSpfAlignment'
    else action = 'addSenderToSpf'
  } else {
    // 'broken': own domain authenticated somewhere, but alignment/crypto still failed.
    verdict = isOwnAuthorizedSender ? 'likelyLegit' : 'possiblyLegit'
    if (dkim.domain && dkim.raw !== 'pass') action = 'fixDkimAuth'
    else if (spf.domain && spf.raw !== 'pass') action = 'fixSpfAuth'
    else if (!dkim.domain) action = 'checkDkimSigning'
    else action = 'checkSpfAlignment'
  }

  return {
    verdict,
    category,
    action,
    domain: from,
    senderName: sender?.name ?? null,
    senderKind: sender?.kind ?? null,
    spf,
    dkim,
    sampleCount
  }
}
