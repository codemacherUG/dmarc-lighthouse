import { t, type MessageKey } from '../../shared/i18n'
import {
  DEFAULT_DATE_RANGE,
  type DateRangePreset,
  type DispositionFilter,
  type DomainHealth,
  type DomainHealthStatus
} from '../../shared/types'

export const DASHBOARD_UI_STATE_STORAGE_KEY = 'dmarc-lighthouse.dashboard-ui-state.v1'

export type AmpelSortOrder = 'status' | 'passRateAsc' | 'volumeDesc' | 'domainAsc'
export type AmpelStatusFilter = 'all' | 'bad' | 'warn' | 'ok'

export type DomainToolAction = 'dmarc' | 'spf' | 'tlsrpt' | 'mtaSts' | 'bimi' | 'rollout' | 'dkim'

export interface DashboardUiState {
  range: DateRangePreset
  disposition: DispositionFilter
  domain: string
  ampelSort: AmpelSortOrder
  ampelCompact: boolean
}

export const DEFAULT_DASHBOARD_UI_STATE: DashboardUiState = {
  range: DEFAULT_DATE_RANGE,
  disposition: 'all',
  domain: '',
  ampelSort: 'status',
  ampelCompact: false
}

type UiStateStorage = Pick<Storage, 'getItem' | 'setItem'>

function isValidRangePreset(value: unknown): value is DateRangePreset {
  return value === '7' || value === '30' || value === '90' || value === 'all'
}

function isValidDisposition(value: unknown): value is DispositionFilter {
  return value === 'all' || value === 'reject' || value === 'not-reject'
}

function isValidAmpelSort(value: unknown): value is AmpelSortOrder {
  return (
    value === 'status' || value === 'passRateAsc' || value === 'volumeDesc' || value === 'domainAsc'
  )
}

export function readDashboardUiState(storage: UiStateStorage | null): DashboardUiState {
  if (!storage) return { ...DEFAULT_DASHBOARD_UI_STATE }
  try {
    const raw = storage.getItem(DASHBOARD_UI_STATE_STORAGE_KEY)
    if (!raw) return { ...DEFAULT_DASHBOARD_UI_STATE }
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ...DEFAULT_DASHBOARD_UI_STATE }
    }
    const obj = parsed as Record<string, unknown>
    return {
      range: isValidRangePreset(obj.range) ? obj.range : DEFAULT_DASHBOARD_UI_STATE.range,
      disposition: isValidDisposition(obj.disposition)
        ? obj.disposition
        : DEFAULT_DASHBOARD_UI_STATE.disposition,
      domain: typeof obj.domain === 'string' ? obj.domain.trim() : '',
      ampelSort: isValidAmpelSort(obj.ampelSort)
        ? obj.ampelSort
        : DEFAULT_DASHBOARD_UI_STATE.ampelSort,
      ampelCompact: Boolean(obj.ampelCompact)
    }
  } catch {
    return { ...DEFAULT_DASHBOARD_UI_STATE }
  }
}

export function writeDashboardUiState(
  storage: UiStateStorage | null,
  patch: Partial<DashboardUiState>
): DashboardUiState {
  const next: DashboardUiState = {
    ...readDashboardUiState(storage),
    ...patch
  }
  if (!storage) return next
  try {
    storage.setItem(DASHBOARD_UI_STATE_STORAGE_KEY, JSON.stringify(next))
  } catch {
    // Ignore storage quota or access errors.
  }
  return next
}

const STATUS_ORDER: Record<DomainHealthStatus, number> = {
  bad: 0,
  warn: 1,
  unknown: 2,
  ok: 3
}

/** Pure filter + sort helper for the Domain-Ampel list. */
export function filterAndSortDomainHealth(
  rows: readonly DomainHealth[],
  options: {
    statusFilter?: AmpelStatusFilter
    query?: string
    sort?: AmpelSortOrder
  } = {}
): DomainHealth[] {
  const statusFilter = options.statusFilter ?? 'all'
  const query = (options.query ?? '').trim().toLowerCase()
  const sort = options.sort ?? 'status'

  const filtered = rows.filter((h) => {
    if (statusFilter !== 'all' && h.status !== statusFilter) return false
    if (!query) return true
    const reasonsText = h.reasons
      .map((key) => t(key as MessageKey))
      .join(' ')
      .toLowerCase()
    const hay = `${h.domain} ${h.dmarcPolicy ?? ''} ${reasonsText}`.toLowerCase()
    return hay.includes(query)
  })

  return [...filtered].sort((a, b) => {
    if (sort === 'passRateAsc') {
      return a.passRate - b.passRate || b.total - a.total || a.domain.localeCompare(b.domain)
    }
    if (sort === 'volumeDesc') {
      return b.total - a.total || a.domain.localeCompare(b.domain)
    }
    if (sort === 'domainAsc') {
      return a.domain.localeCompare(b.domain)
    }
    const byStatus = STATUS_ORDER[a.status] - STATUS_ORDER[b.status]
    if (byStatus !== 0) return byStatus
    return b.total - a.total || a.domain.localeCompare(b.domain)
  })
}

/** Map actionable domain-health reason keys to direct wizard/tool shortcuts. */
export function ampelQuickActionsForReasons(
  reasons: readonly string[]
): Array<{ action: DomainToolAction; labelKey: MessageKey }> {
  const out: Array<{ action: DomainToolAction; labelKey: MessageKey }> = []
  const seen = new Set<DomainToolAction>()
  const push = (action: DomainToolAction, labelKey: MessageKey): void => {
    if (seen.has(action)) return
    seen.add(action)
    out.push({ action, labelKey })
  }

  for (const key of reasons) {
    if (key === 'health.reason.noDmarc') {
      push('dmarc', 'health.action.dmarcWizard')
    } else if (key === 'health.reason.noSpf' || key === 'health.reason.spfInvalid') {
      push('spf', 'health.action.spfWizard')
    } else if (key === 'health.reason.policyNone' || key === 'health.reason.policyWeak') {
      push('rollout', 'health.action.rollout')
    } else if (key === 'health.reason.dkimMissing') {
      push('dkim', 'health.action.dkim')
    }
  }
  return out
}
