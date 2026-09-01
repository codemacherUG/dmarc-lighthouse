import type { CloudPrefix } from '../../shared/ipcidr'
import type { RolloutSimulationMode } from '../../shared/rollout'
import type { AnalyzeResult, DomainHealth, IpInfo, SendingService, SettingsPublic } from '../../shared/types'

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
  sendingServices: [] as SendingService[],
  selectedDetailIp: null as string | null,
  domainHealthCache: [] as DomainHealth[],
  simulationMode: 'off' as RolloutSimulationMode,
  simulationDomain: '' as string,
  domainHealthToken: 0,
  /** Merged SPF CIDR prefixes for report domains (for IP badges). */
  spfPrefixes: [] as CloudPrefix[],
  /** SPF CIDR prefixes keyed by report domain for source classification. */
  spfPrefixesByDomain: new Map<string, CloudPrefix[]>(),
  spfExpandToken: 0
}

export function clearDrill(): void {
  Object.keys(state.drill).forEach((k) => delete state.drill[k as keyof DrillFilters])
}
