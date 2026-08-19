import type {
  AccountSettingsInput,
  AnalyzeProgress,
  AnalyzeResult,
  BimiCheckResult,
  DnsCheckResult,
  DomainHealth,
  SpfExpandResult,
  GeoLiteDownloadResult,
  GeoLiteStatus,
  AppTheme,
  GlobalSettings,
  IpInfo,
  CreateMailboxResult,
  ListMailboxesResult,
  RdapInfo,
  ReportRow,
  SettingsPublic,
  TestConnectionResult,
  TransportSecurityResult,
  UpdateStatusPayload,
  EmailInspectResponse,
  EmailInspectResult
} from '../shared/types'

export interface DmarcLighthouseApi {
  loadSettings: () => Promise<SettingsPublic>
  saveAccount: (input: AccountSettingsInput) => Promise<SettingsPublic>
  deleteAccount: (id: string) => Promise<SettingsPublic>
  setActiveAccount: (id: string) => Promise<SettingsPublic>
  saveGlobalSettings: (input: GlobalSettings) => Promise<SettingsPublic>
  previewTheme: (theme: AppTheme) => Promise<void>
  oauthLogin: (accountId: string) => Promise<SettingsPublic>
  oauthDisconnect: (accountId: string) => Promise<SettingsPublic>
  testConnection: (input: AccountSettingsInput) => Promise<TestConnectionResult>
  listMailboxes: (input: AccountSettingsInput) => Promise<ListMailboxesResult>
  createMailbox: (input: AccountSettingsInput, path: string) => Promise<CreateMailboxResult>
  fetchSaved: (accountId?: string | null) => Promise<AnalyzeResult>
  loadCache: (accountId?: string | null) => Promise<AnalyzeResult | null>
  clearCache: (accountId?: string | null) => Promise<{ ok: boolean; message: string }>
  resolveIps: (ips: string[]) => Promise<IpInfo[]>
  lookupRdap: (ip: string) => Promise<RdapInfo>
  checkDns: (domain: string, selectors?: string[]) => Promise<DnsCheckResult>
  checkBimi: (domain: string, selector?: string) => Promise<BimiCheckResult>
  expandSpf: (domain: string, record?: string | null) => Promise<SpfExpandResult>
  checkTransport: (domain: string) => Promise<TransportSecurityResult>
  healthBatch: (reports: ReportRow[]) => Promise<DomainHealth[]>
  geoLiteStatus: () => Promise<GeoLiteStatus>
  downloadGeoLite: (licenseKey?: string) => Promise<GeoLiteDownloadResult>
  openFiles: () => Promise<AnalyzeResult | null>
  parseBuffers: (files: Array<{ name: string; data: ArrayBuffer }>) => Promise<AnalyzeResult>
  openEmailFile: () => Promise<EmailInspectResponse | null>
  parseEmail: (input: {
    name?: string
    data?: ArrayBuffer
    text?: string
  }) => Promise<EmailInspectResponse>
  exportEmailInspectPdf: (result: EmailInspectResult) => Promise<{ ok: boolean; message: string }>
  exportSave: (
    result: AnalyzeResult,
    format: 'json' | 'csv'
  ) => Promise<{ ok: boolean; message: string }>
  exportReportZip: (report: ReportRow) => Promise<{ ok: boolean; message: string }>
  exportPdfReport: (
    result: AnalyzeResult,
    options?: { domain?: string | null }
  ) => Promise<{ ok: boolean; message: string }>
  chooseReportDir: () => Promise<{ ok: boolean; dir: string }>
  runMonthlyReport: () => Promise<{ ok: boolean; message: string }>
  getAppVersion: () => Promise<string>
  openThirdPartyNotices: () => Promise<{ ok: boolean; message: string }>
  checkForUpdates: () => Promise<{ ok: boolean; message: string }>
  downloadUpdate: () => Promise<{ ok: boolean; message: string }>
  installUpdate: () => Promise<{ ok: boolean; message: string }>
  onProgress: (callback: (progress: AnalyzeProgress) => void) => () => void
  onResult: (callback: (result: AnalyzeResult) => void) => () => void
  onUpdateStatus: (callback: (payload: UpdateStatusPayload) => void) => () => void
}

declare global {
  interface Window {
    api: DmarcLighthouseApi
    __dmarcScreenshot?: {
      prepareDemo: (locale: 'de' | 'en') => Promise<void>
      openSettingsDemo: () => void
      closeSettings: () => void
      openRolloutDemo: () => void
      closeRollout: () => void
      openDnsDemo: () => void
      closeDns: () => void
      openDiagnosisDemo: () => void
      closeDiagnosis: () => void
      openEmailInspectDemo: () => { width: number; height: number }
      closeEmailInspect: () => void
      setTheme: (theme: AppTheme) => void
      scrollTo: (selector: string) => Promise<void>
      selectFirstReport: () => Promise<void>
      prepareFullPage: () => Promise<{ width: number; height: number }>
    }
  }
}
