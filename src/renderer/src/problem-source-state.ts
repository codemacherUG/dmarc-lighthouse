import type { CloudPrefix } from '../../shared/ipcidr'

export const PROBLEM_SOURCE_IGNORE_STORAGE_KEY = 'dmarc-lighthouse.problem-source-ignores.v1'

type ProblemSourceStateStorage = Pick<Storage, 'getItem' | 'setItem'>

function accountKey(accountId: string | null): string {
  return accountId?.trim() || '_default'
}

export function findSpfPrefixesForDomain(
  prefixesByDomain: ReadonlyMap<string, CloudPrefix[]>,
  domain: string | null
): CloudPrefix[] {
  const normalized = (domain ?? '').trim().toLowerCase()
  const direct = prefixesByDomain.get(normalized)
  if (direct) return direct
  let bestDomain = ''
  let best: CloudPrefix[] = []
  for (const [candidate, prefixes] of prefixesByDomain) {
    if (normalized.endsWith(`.${candidate}`) && candidate.length > bestDomain.length) {
      bestDomain = candidate
      best = prefixes
    }
  }
  return best
}

export function problemSourceIgnoreKey(sourceIp: string, headerFrom: string | null): string {
  return `${(headerFrom ?? '').trim().toLowerCase()}|${sourceIp.trim().toLowerCase()}`
}

export function readIgnoredProblemSourceKeys(
  storage: ProblemSourceStateStorage | null,
  accountId: string | null
): Set<string> {
  if (!storage) return new Set()
  try {
    const value: unknown = JSON.parse(storage.getItem(PROBLEM_SOURCE_IGNORE_STORAGE_KEY) ?? '{}')
    if (!value || typeof value !== 'object' || Array.isArray(value)) return new Set()
    const accountValue = (value as Record<string, unknown>)[accountKey(accountId)]
    if (!Array.isArray(accountValue)) return new Set()
    return new Set(
      accountValue.filter((key): key is string => typeof key === 'string' && key !== '')
    )
  } catch {
    return new Set()
  }
}

export function writeIgnoredProblemSourceKeys(
  storage: ProblemSourceStateStorage | null,
  accountId: string | null,
  ignoredKeys: ReadonlySet<string>
): void {
  if (!storage) return
  try {
    const stored: unknown = JSON.parse(storage.getItem(PROBLEM_SOURCE_IGNORE_STORAGE_KEY) ?? '{}')
    const value =
      stored && typeof stored === 'object' && !Array.isArray(stored)
        ? { ...(stored as Record<string, unknown>) }
        : {}
    const key = accountKey(accountId)
    if (ignoredKeys.size) value[key] = [...ignoredKeys].sort()
    else delete value[key]
    storage.setItem(PROBLEM_SOURCE_IGNORE_STORAGE_KEY, JSON.stringify(value))
  } catch {
    // The dashboard remains usable when web storage is unavailable.
  }
}
