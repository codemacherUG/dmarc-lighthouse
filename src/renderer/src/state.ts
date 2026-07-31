import type { AnalyzeResult, DomainHealth, IpInfo, SettingsPublic } from '../../shared/types'

export type DrillFilters = { org?: string; sourceIp?: string; headerFrom?: string }

/** Mutable app state shared across renderer modules. */
export const state = {
  selectedReportId: null as string | null,
  busy: false,
  settings: null as SettingsPublic | null,
  /** Account currently edited in the settings dialog (null = new account). */
  dialogAccountId: null as string | null,
  fullResult: null as AnalyzeResult | null,
  viewResult: null as AnalyzeResult | null,
  /** Drill-down filters set by clicking rows in the aggregate tables. */
  drill: {} as DrillFilters,
  ipLabelCache: new Map<string, IpInfo>(),
  selectedDetailIp: null as string | null,
  domainHealthCache: [] as DomainHealth[],
  domainHealthToken: 0
}

export function clearDrill(): void {
  Object.keys(state.drill).forEach((k) => delete state.drill[k as keyof DrillFilters])
}
