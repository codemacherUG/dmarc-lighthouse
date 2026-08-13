import type { AppLocale } from './i18n'
import type { SenderKind } from './sender'
import type { AppTheme } from './theme'

export type { AppLocale, AppTheme, SenderKind }

export type ProviderPreset = 'gmail' | 'outlook' | 'microsoft' | 'custom'

export type AuthMode = 'password' | 'oauth'

export type OAuthProvider = 'google' | 'microsoft'

export type DateRangePreset = 'all' | '7' | '30' | '90' | 'custom'

export type UpdateStatusPayload =
  | { status: 'checking' }
  | { status: 'available'; version: string }
  | { status: 'not-available'; version: string }
  | { status: 'downloading'; percent: number; transferred: number; total: number }
  | { status: 'verifying'; version: string }
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
  microsoft: { host: 'outlook.office365.com', port: 993, secure: true },
  custom: { host: '', port: 993, secure: true }
}

/** Resolved connection used by the IMAP layer. */
export interface ImapConnectionInput {
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  authMode: AuthMode
  /** Present for password auth. */
  password?: string
  /** Present for OAuth (XOAUTH2) auth. */
  accessToken?: string
  mailbox: string
  /** When set and different from `mailbox`, fetched messages are moved here after import. */
  archiveMailbox: string
  subjectFilter: string
  markSeenAfterFetch: boolean
}

/** Account form input from the renderer. `id` is null for a new account. */
export interface AccountSettingsInput {
  id: string | null
  /** Custom display name; empty = use suggested domain name. */
  name: string
  provider: ProviderPreset
  authMode: AuthMode
  host: string
  port: number
  secure: boolean
  user: string
  password: string
  mailbox: string
  /** Empty = do not move messages after fetch. */
  archiveMailbox: string
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
  authMode: AuthMode
  host: string
  port: number
  secure: boolean
  user: string
  mailbox: string
  archiveMailbox: string
  subjectFilter: string
  hasPassword: boolean
  /** True when a refresh token is stored for OAuth. */
  hasOAuth: boolean
  markSeenAfterFetch: boolean
}

/** IMAP folder entry returned by LIST. */
export interface MailboxListEntry {
  path: string
  name: string
  /** Special-use flag if the server reports one (e.g. \\Archive). */
  specialUse?: string
}

export interface ListMailboxesResult {
  ok: boolean
  message: string
  mailboxes: MailboxListEntry[]
}

export interface CreateMailboxResult {
  ok: boolean
  message: string
  path: string
  created: boolean
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
  /** UI color scheme. `auto` follows the operating system. */
  theme: AppTheme
  /** Optional Google OAuth client ID (desktop/public PKCE client). */
  oauthGoogleClientId: string
  /** Optional Microsoft Entra / Azure AD application (client) ID. */
  oauthMicrosoftClientId: string
  /** Master switch for IP enrichment (PTR still runs when off). */
  enrichmentEnabled: boolean
  /** Use HTTPS geo lookup when GeoLite2 DBs are missing (opt-in). */
  geoIpOnlineFallback: boolean
  /**
   * MaxMind license key for GeoLite2 download.
   * Write-only: load always returns ''; non-empty on save replaces the stored key.
   */
  maxmindLicenseKey: string
  /** Whether an encrypted MaxMind license key is stored. */
  hasMaxmindLicenseKey: boolean
  /** Query DNSBLs (Spamhaus ZEN, dnswl). */
  dnsblEnabled: boolean
  /** Match source IPs against cloud provider prefix lists. */
  cloudRangesEnabled: boolean
  /** Allow on-demand RDAP/WHOIS lookups. */
  rdapEnabled: boolean
  /** Persist dashboard filter: hide Google SPF-fail / DKIM-pass noise. */
  hideGoogleNoise: boolean
  /** Write a PDF management report for the finished month, once per month. */
  pdfMonthlyEnabled: boolean
  /** Output folder for monthly reports; empty = Documents/DMARC Lighthouse. */
  pdfMonthlyDir: string
  /** Read-only: when the last monthly report was written (ISO), '' if never. */
  pdfMonthlyLastRun: string
}

export interface SettingsPublic {
  accounts: AccountPublic[]
  activeAccountId: string | null
  global: GlobalSettings
}

export interface AnalyzeProgress {
  phase: 'connecting' | 'searching' | 'fetching' | 'parsing' | 'moving' | 'done' | 'error'
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

/** Sanitized DMARC failure / forensic (RUF) report — no message bodies. */
export interface ForensicReportRow {
  id: string
  reportId: string | null
  orgName: string | null
  reportedDomain: string | null
  arrivalDate: string | null
  sourceIp: string | null
  authFailure: string | null
  deliveryResult: string | null
  envelopeFrom: string | null
  headerFrom: string | null
  originalRcptTo: string | null
  authenticationResults: string | null
  subject: string | null
  feedbackType: string | null
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

/**
 * Why delivered messages failed DMARC — the answer decides what to do next.
 * - `forwarder`: receiver flagged forwarding / mailing list, usually not actionable
 * - `thirdParty`: signed or sent under a foreign domain — an ESP without alignment
 * - `broken`: own domain authenticated but alignment or the signature failed
 * - `unauthenticated`: no SPF and no DKIM at all — the spoofing candidate
 */
export type FailCategory = 'forwarder' | 'thirdParty' | 'broken' | 'unauthenticated'

/** Message counts per failure category. */
export type FailCategoryCounts = Partial<Record<FailCategory, number>>

/** Source IP with delivered auth-fails — useful during DMARC rollout. */
export interface ProblemSourceRow {
  sourceIp: string
  count: number
  spfFail: number
  dkimFail: number
  /** Most frequent header-from among problem rows for this IP. */
  headerFrom: string | null
  /** Other IPs in the same ASN/provider + From group (after enrichment). */
  extraIps?: string[]
  /** Messages per failure category. */
  categories?: FailCategoryCounts
  /** Dominant failure category by message count. */
  category?: FailCategory | null
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
  /** Unhealthy outcomes (delivered auth-fails) grouped by source IP. */
  problemSources: ProblemSourceRow[]
}

/** Outcome of a local file import. */
export interface ImportSummary {
  /** Reports newly stored in the cache. */
  added: number
  /** Reports that replaced an already cached report with the same ID. */
  updated: number
  /** Forensic reports newly stored. */
  addedForensic: number
  /** False when the cache write failed and the data only exists for this session. */
  persisted: boolean
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
  /** Forensic / RUF failure reports (sanitized). */
  forensicReports: ForensicReportRow[]
  skipped: number
  errors: string[]
  /** True when result came (partly) from local cache. */
  fromCache?: boolean
  /** Newly parsed report count in this fetch. */
  newReports?: number
  /** Newly parsed forensic reports in this fetch. */
  newForensicReports?: number
  /** Source IPs that were not seen in any earlier fetch of this account. */
  newSourceIps?: string[]
  /** Account this result belongs to (set for IMAP fetches). */
  accountId?: string
  /** Set for local file imports. */
  imported?: ImportSummary
}

export interface TestConnectionResult {
  ok: boolean
  message: string
  mailboxExists?: number
}

export type GeoSource = 'maxmind' | 'online' | 'none'

export interface IpInfo {
  ip: string
  ptr: string | null
  /** Sending service (e.g. "Amazon SES") or the network label as fallback. */
  provider: string | null
  /** What kind of service `provider` is, when it was recognized. */
  senderKind: SenderKind | null
  country: string | null
  countryCode: string | null
  city: string | null
  /** WGS84 latitude from GeoLite2 / online lookup, when available. */
  lat: number | null
  /** WGS84 longitude from GeoLite2 / online lookup, when available. */
  lon: number | null
  asn: number | null
  asOrg: string | null
  cloudProvider: string | null
  dnsblHits: string[]
  geoSource: GeoSource
}

export type DomainHealthStatus = 'ok' | 'warn' | 'bad' | 'unknown'

/** Per-domain volume stats from aggregate reports (no DNS yet). */
export interface DomainStats {
  domain: string
  total: number
  passing: number
  failing: number
  passRate: number
  /** DKIM selectors seen in report auth results. */
  dkimSelectors: string[]
}

export interface DomainHealth extends DomainStats {
  dmarcPolicy: string | null
  spfOk: boolean | null
  dkimOk: boolean | null
  status: DomainHealthStatus
  /** i18n message keys explaining the status. */
  reasons: string[]
}

export interface RdapInfo {
  ip: string
  org: string | null
  country: string | null
  cidr: string | null
  abuseEmail: string | null
  rawSummary: string | null
  error?: string
}

export interface GeoLiteStatus {
  cityDb: boolean
  asnDb: boolean
  dir: string
}

export interface GeoLiteDownloadResult {
  ok: boolean
  message: string
}

export interface DkimSelectorCheck {
  selector: string
  found: boolean
  record: string | null
  error?: string
}

export type DnsResolverMode = 'authoritative' | 'recursive'

export interface DnsResolverInfo {
  mode: DnsResolverMode
  /** Zone whose NS were used (authoritative only). */
  zone: string | null
  /** NS hostnames (authoritative only). */
  nameservers: string[]
}

export interface DnsCheckResult {
  domain: string
  dmarc: {
    found: boolean
    records: string[]
    policy: string | null
    rua: string | null
    ruf: string | null
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
  resolver?: DnsResolverInfo
  checkedAt: string
}

export interface TlsRptCheck {
  found: boolean
  records: string[]
  /** Report targets from `rua=` (mailto: or https:). */
  rua: string[]
  error?: string
}

export interface MtaStsPolicy {
  version: string | null
  mode: 'enforce' | 'testing' | 'none' | null
  mx: string[]
  maxAgeSeconds: number | null
}

export interface MtaStsCheck {
  found: boolean
  id: string | null
  records: string[]
  policyUrl: string
  policy: MtaStsPolicy | null
  error?: string
  policyError?: string
}

export interface DaneMxCheck {
  host: string
  preference: number
  /** Rendered TLSA records, e.g. `3 1 1 a1b2…`. */
  tlsa: string[]
  found: boolean
  error?: string
}

export interface DaneCheck {
  mx: DaneMxCheck[]
  error?: string
}

export type TransportSecurityStatus = 'ok' | 'warn' | 'bad' | 'unknown'

/** One finding from the transport check; `level` is why the badge is not OK. */
export interface TransportReason {
  key: string
  level: Exclude<TransportSecurityStatus, 'unknown'>
}

/** SMTP transport hardening: TLS-RPT reporting, MTA-STS policy, DANE/TLSA. */
export interface TransportSecurityResult {
  domain: string
  tlsrpt: TlsRptCheck
  mtaSts: MtaStsCheck
  dane: DaneCheck
  status: TransportSecurityStatus
  reasons: TransportReason[]
  checkedAt: string
}

/** Expanded SPF allowlist (ip4/ip6/include/a/mx/redirect → CIDRs). */
export interface SpfExpandResult {
  domain: string
  record: string | null
  cidrs: string[]
  lookups: number
  errors: string[]
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
  /** Drill-down: only records from this source IP (comma-separated for a group). */
  sourceIp?: string
  /** Drill-down: only records with this header-from domain. */
  headerFrom?: string
  /**
   * Hide Google forwarding / report-echo artifacts:
   * Google source IP + SPF fail + DKIM pass + DMARC pass.
   * Uses well-known Google IP prefixes; `googleIps` from enrichment is optional extra.
   */
  hideGoogleNoise?: boolean
  /** Extra source IPs identified as Google (cloud / PTR / ASN). */
  googleIps?: ReadonlySet<string>
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
    volumeByDay: [],
    problemSources: []
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
    forensicReports: [],
    skipped: 0,
    errors: []
  }
}
