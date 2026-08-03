import { ElectronAPI } from '@electron-toolkit/preload'
import type {
  AccountSettingsInput,
  AnalyzeProgress,
  AnalyzeResult,
  DnsCheckResult,
  DomainHealth,
  GeoLiteDownloadResult,
  GeoLiteStatus,
  GlobalSettings,
  IpInfo,
  CreateMailboxResult,
  ListMailboxesResult,
  RdapInfo,
  ReportRow,
  SettingsPublic,
  TestConnectionResult,
  UpdateStatusPayload
} from '../shared/types'

export interface DmarcViewerApi {
  loadSettings: () => Promise<SettingsPublic>
  saveAccount: (input: AccountSettingsInput) => Promise<SettingsPublic>
  deleteAccount: (id: string) => Promise<SettingsPublic>
  setActiveAccount: (id: string) => Promise<SettingsPublic>
  saveGlobalSettings: (input: GlobalSettings) => Promise<SettingsPublic>
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
  healthBatch: (reports: ReportRow[]) => Promise<DomainHealth[]>
  geoLiteStatus: () => Promise<GeoLiteStatus>
  downloadGeoLite: (licenseKey?: string) => Promise<GeoLiteDownloadResult>
  openFiles: () => Promise<AnalyzeResult | null>
  parsePaths: (paths: string[]) => Promise<AnalyzeResult>
  getPathForFile: (file: File) => string
  exportSave: (
    result: AnalyzeResult,
    format: 'json' | 'csv'
  ) => Promise<{ ok: boolean; message: string }>
  getAppVersion: () => Promise<string>
  openThirdPartyNotices: () => Promise<{ ok: boolean; message: string }>
  checkForUpdates: () => Promise<{ ok: boolean; message: string }>
  installUpdate: () => Promise<{ ok: boolean; message: string }>
  onProgress: (callback: (progress: AnalyzeProgress) => void) => () => void
  onResult: (callback: (result: AnalyzeResult) => void) => () => void
  onUpdateStatus: (callback: (payload: UpdateStatusPayload) => void) => () => void
}

declare global {
  interface Window {
    electron: ElectronAPI
    api: DmarcViewerApi
    __dmarcScreenshot?: {
      prepareDemo: () => Promise<void>
      openSettingsDemo: () => void
      closeSettings: () => void
      scrollTo: (selector: string) => Promise<void>
      selectFirstReport: () => Promise<void>
    }
  }
}
