import type { AppLocale } from './i18n'

export type { AppLocale }

export type ProviderPreset = 'gmail' | 'outlook' | 'custom'

export type DateRangePreset = 'all' | '7' | '30' | '90' | 'custom'

export type UpdateStatusPayload =
  | { status: 'checking' }
  | { status: 'available'; version: string }
  | { status: 'not-available'; version: string }
  | { status: 'downloading'; percent: number; transferred: number; total: number }
  | { status: 'downloaded'; version: string }
  | { status: 'error'; message: string }

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

/** Resolved connection used by the IMAP layer (password always present). */
export interface ImapConnectionInput {
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  password: string
  mailbox: string
  subjectFilter: string
  markSeenAfterFetch: boolean
}

/** Account form input from the renderer. `id` is null for a new account. */
export interface AccountSettingsInput {
  id: string | null
  /** Custom display name; empty = use suggested domain name. */
  name: string
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  password: string
  mailbox: string
  subjectFilter: string
  markSeenAfterFetch: boolean
}

export interface AccountPublic {
  id: string
  /** Stored custom name (may be empty). */
  name: string
  /** Name shown in the UI (custom or suggested domain). */
  label: string
  /** Suggested default name (usually the email domain). */
  suggestedName: string
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  mailbox: string
  subjectFilter: string
  hasPassword: boolean
  markSeenAfterFetch: boolean
}

export interface GlobalSettings {
  autoFetchMinutes: number
  notifyOnFail: boolean
  /** Alert when the 7-day pass rate falls below this percentage. 0 = off. */
  passRateAlertThreshold: number
  /** Alert when a previously unseen source IP shows up in new reports. */
  notifyNewSource: boolean
  /** Ignore list for source alerts: IPs or prefixes with `*`, comma/newline separated. */
  ignoredSources: string
  /** Keep running in the system tray when the window is closed. */
  runInTray: boolean
  /** Launch the app automatically when the user logs in. */
  openAtLogin: boolean
  /** UI language. */
  language: AppLocale
}

export interface SettingsPublic {
  accounts: AccountPublic[]
  activeAccountId: string | null
  global: GlobalSettings
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
  /** DKIM selectors seen in auth_results (for DNS checks). */
  dkimSelectors: string[]
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
  /** Source IPs that were not seen in any earlier fetch of this account. */
  newSourceIps?: string[]
  /** Account this result belongs to (set for IMAP fetches). */
  accountId?: string
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

export interface DkimSelectorCheck {
  selector: string
  found: boolean
  record: string | null
  error?: string
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
  dkim: {
    selectors: DkimSelectorCheck[]
  }
  checkedAt: string
}

export interface DashboardFilter {
  range: DateRangePreset
  /** Custom range start (YYYY-MM-DD), only used when range === 'custom'. */
  from?: string
  /** Custom range end (YYYY-MM-DD), only used when range === 'custom'. */
  to?: string
  domain: string
  /** Drill-down: only reports from this reporting organization. */
  org?: string
  /** Drill-down: only records from this source IP. */
  sourceIp?: string
  /** Drill-down: only records with this header-from domain. */
  headerFrom?: string
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
