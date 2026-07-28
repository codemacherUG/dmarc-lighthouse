export type ProviderPreset = 'gmail' | 'outlook' | 'custom'

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
}

export interface AnalyzeProgress {
  phase: 'connecting' | 'searching' | 'fetching' | 'parsing' | 'done' | 'error'
  processed: number
  total: number
  parsed: number
  skipped: number
  message?: string
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
}

export interface VolumePoint {
  date: string
  total: number
  passing: number
  failing: number
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
}

export interface TestConnectionResult {
  ok: boolean
  message: string
  mailboxExists?: number
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
