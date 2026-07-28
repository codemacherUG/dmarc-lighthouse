export type ProviderPreset = 'gmail' | 'outlook' | 'custom'

export type DateRangePreset = 'all' | '7' | '30' | '90'

export interface ProviderDefaults {
  host: string
  port: number
  secure: boolean
}

export const PROVIDER_PRESETS: Record<ProviderPreset, ProviderDefaults> = {
  gmail: { host: 'imap.gmail.com', port: 993, secure: true },
  outlook: { host: 'outlook.office365.com', port: 993, secure: true },
  custom: { host: '', port: 993, secure: true }
}

export interface ImapConnectionInput {
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  password: string
  mailbox: string
  subjectFilter: string
  autoFetchMinutes: number
  notifyOnFail: boolean
  markSeenAfterFetch: boolean
}

export interface SavedSettingsPublic {
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  mailbox: string
  subjectFilter: string
  hasPassword: boolean
  autoFetchMinutes: number
  notifyOnFail: boolean
  markSeenAfterFetch: boolean
}

export interface AnalyzeProgress {
  phase: 'connecting' | 'searching' | 'fetching' | 'parsing' | 'done' | 'error'
  processed: number
  total: number
  parsed: number
  skipped: number
  message?: string
}

export interface SerializedReason {
  type: string | null
  comment: string | null
}

export interface SerializedRecord {
  sourceIp: string
  count: number
  disposition: string | null
  dkimResult: string | null
  spfResult: string | null
  headerFrom: string | null
  dkimDomain: string | null
  spfDomain: string | null
  passesDmarc: boolean
  reasons: SerializedReason[]
}

export interface ReportRow {
  reportId: string
  orgName: string
  domain: string
  dateBegin: string
  dateEnd: string
  total: number
  passing: number
  failing: number
  passRate: number
  policyP: string | null
  records: SerializedRecord[]
}

export interface AlignmentBreakdown {
  pass: number
  fail: number
  other: number
}

export interface NamedBucket {
  name: string
  count: number
  passing: number
  failing: number
  passRate: number
  /** Optional labels for IP rows (PTR / known provider). */
  label?: string | null
  provider?: string | null
}

export interface VolumePoint {
  date: string
  total: number
  passing: number
  failing: number
  passRate: number
}

/** Kibana-ähnliche Dashboard-Aggregationen über alle Records. */
export interface DashboardData {
  dmarc: AlignmentBreakdown
  spf: AlignmentBreakdown
  dkim: AlignmentBreakdown
  dispositions: NamedBucket[]
  byOrg: NamedBucket[]
  bySourceIp: NamedBucket[]
  byHeaderFrom: NamedBucket[]
  volumeByDay: VolumePoint[]
}

export interface AnalyzeResult {
  aggregate: {
    reportCount: number
    total: number
    passing: number
    failing: number
    passRate: number
    dateBegin: string | null
    dateEnd: string | null
    domains: string[]
  }
  dashboard: DashboardData
  reports: ReportRow[]
  skipped: number
  errors: string[]
  /** True when result came (partly) from local cache. */
  fromCache?: boolean
  /** Newly parsed report count in this fetch. */
  newReports?: number
}

export interface TestConnectionResult {
  ok: boolean
  message: string
  mailboxExists?: number
}

export interface IpInfo {
  ip: string
  ptr: string | null
  provider: string | null
}

export interface DnsCheckResult {
  domain: string
  dmarc: {
    found: boolean
    records: string[]
    policy: string | null
    rua: string | null
    error?: string
  }
  spf: {
    found: boolean
    records: string[]
    error?: string
  }
  checkedAt: string
}

export interface DashboardFilter {
  range: DateRangePreset
  domain: string
}

export function emptyDashboard(): DashboardData {
  return {
    dmarc: { pass: 0, fail: 0, other: 0 },
    spf: { pass: 0, fail: 0, other: 0 },
    dkim: { pass: 0, fail: 0, other: 0 },
    dispositions: [],
    byOrg: [],
    bySourceIp: [],
    byHeaderFrom: [],
    volumeByDay: []
  }
}

export function emptyAnalyzeResult(): AnalyzeResult {
  return {
    aggregate: {
      reportCount: 0,
      total: 0,
      passing: 0,
      failing: 0,
      passRate: 0,
      dateBegin: null,
      dateEnd: null,
      domains: []
    },
    dashboard: emptyDashboard(),
    reports: [],
    skipped: 0,
    errors: []
  }
}
