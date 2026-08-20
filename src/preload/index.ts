import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron'
import type {
  AccountSettingsInput,
  AnalyzeProgress,
  AnalyzeResult,
  BimiCheckResult,
  DnsCheckResult,
  DnsHistoryResult,
  DomainHealth,
  SpfExpandResult,
  GeoLiteDownloadResult,
  GeoLiteStatus,
  GlobalSettings,
  AppTheme,
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

const api = {
  loadSettings: (): Promise<SettingsPublic> => ipcRenderer.invoke('settings:load'),
  saveAccount: (input: AccountSettingsInput): Promise<SettingsPublic> =>
    ipcRenderer.invoke('settings:saveAccount', input),
  deleteAccount: (id: string): Promise<SettingsPublic> =>
    ipcRenderer.invoke('settings:deleteAccount', id),
  setActiveAccount: (id: string): Promise<SettingsPublic> =>
    ipcRenderer.invoke('settings:setActiveAccount', id),
  saveGlobalSettings: (input: GlobalSettings): Promise<SettingsPublic> =>
    ipcRenderer.invoke('settings:saveGlobal', input),
  previewTheme: (theme: AppTheme): Promise<void> =>
    ipcRenderer.invoke('settings:previewTheme', theme),
  oauthLogin: (accountId: string): Promise<SettingsPublic> =>
    ipcRenderer.invoke('oauth:login', accountId),
  oauthDisconnect: (accountId: string): Promise<SettingsPublic> =>
    ipcRenderer.invoke('oauth:disconnect', accountId),
  testConnection: (input: AccountSettingsInput): Promise<TestConnectionResult> =>
    ipcRenderer.invoke('imap:test', input),
  listMailboxes: (input: AccountSettingsInput): Promise<ListMailboxesResult> =>
    ipcRenderer.invoke('imap:listMailboxes', input),
  createMailbox: (input: AccountSettingsInput, path: string): Promise<CreateMailboxResult> =>
    ipcRenderer.invoke('imap:createMailbox', input, path),
  fetchSaved: (accountId?: string | null): Promise<AnalyzeResult> =>
    ipcRenderer.invoke('imap:fetchSaved', accountId ?? null),
  loadCache: (accountId?: string | null): Promise<AnalyzeResult | null> =>
    ipcRenderer.invoke('cache:load', accountId ?? null),
  clearCache: (accountId?: string | null): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('cache:clear', accountId ?? null),
  resolveIps: (ips: string[]): Promise<IpInfo[]> => ipcRenderer.invoke('ip:resolve', ips),
  lookupRdap: (ip: string): Promise<RdapInfo> => ipcRenderer.invoke('ip:rdap', ip),
  checkDns: (domain: string, selectors?: string[]): Promise<DnsCheckResult> =>
    ipcRenderer.invoke('dns:check', domain, selectors ?? []),
  checkBimi: (domain: string, selector?: string): Promise<BimiCheckResult> =>
    ipcRenderer.invoke('dns:bimi', domain, selector ?? 'default'),
  expandSpf: (domain: string, record?: string | null): Promise<SpfExpandResult> =>
    ipcRenderer.invoke('dns:expandSpf', domain, record ?? null),
  checkTransport: (domain: string): Promise<TransportSecurityResult> =>
    ipcRenderer.invoke('dns:transport', domain),
  dnsHistory: (domain: string): Promise<DnsHistoryResult> =>
    ipcRenderer.invoke('dns:history', domain),
  healthBatch: (reports: ReportRow[]): Promise<DomainHealth[]> =>
    ipcRenderer.invoke('dns:healthBatch', reports),
  geoLiteStatus: (): Promise<GeoLiteStatus> => ipcRenderer.invoke('enrichment:geoLiteStatus'),
  downloadGeoLite: (licenseKey?: string): Promise<GeoLiteDownloadResult> =>
    ipcRenderer.invoke('enrichment:downloadGeoLite', licenseKey),
  openFiles: (): Promise<AnalyzeResult | null> => ipcRenderer.invoke('files:open'),
  parseBuffers: (files: Array<{ name: string; data: ArrayBuffer }>): Promise<AnalyzeResult> =>
    ipcRenderer.invoke('files:parseBuffers', files),
  openEmailFile: (): Promise<EmailInspectResponse | null> => ipcRenderer.invoke('email:open'),
  parseEmail: (input: {
    name?: string
    data?: ArrayBuffer
    text?: string
  }): Promise<EmailInspectResponse> => ipcRenderer.invoke('email:parse', input),
  exportEmailInspectPdf: (result: EmailInspectResult): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('email:pdf', result),
  exportSave: (
    result: AnalyzeResult,
    format: 'json' | 'csv'
  ): Promise<{ ok: boolean; message: string }> => ipcRenderer.invoke('export:save', result, format),
  exportReportZip: (report: ReportRow): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('export:reportZip', report),
  exportPdfReport: (
    result: AnalyzeResult,
    options?: { domain?: string | null }
  ): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('report:pdf', result, options ?? {}),
  chooseReportDir: (): Promise<{ ok: boolean; dir: string }> =>
    ipcRenderer.invoke('report:chooseDir'),
  runMonthlyReport: (): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('report:monthlyNow'),
  getAppVersion: (): Promise<string> => ipcRenderer.invoke('app:getVersion'),
  openThirdPartyNotices: (): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('app:openThirdPartyNotices'),
  checkForUpdates: (): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('update:check'),
  downloadUpdate: (): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('update:download'),
  installUpdate: (): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('update:install'),
  onProgress: (callback: (progress: AnalyzeProgress) => void): (() => void) => {
    const listener = (_event: IpcRendererEvent, progress: AnalyzeProgress): void => {
      callback(progress)
    }
    ipcRenderer.on('imap:progress', listener)
    return () => {
      ipcRenderer.removeListener('imap:progress', listener)
    }
  },
  onResult: (callback: (result: AnalyzeResult) => void): (() => void) => {
    const listener = (_event: IpcRendererEvent, result: AnalyzeResult): void => {
      callback(result)
    }
    ipcRenderer.on('imap:result', listener)
    return () => {
      ipcRenderer.removeListener('imap:result', listener)
    }
  },
  onUpdateStatus: (callback: (payload: UpdateStatusPayload) => void): (() => void) => {
    const listener = (_event: IpcRendererEvent, payload: UpdateStatusPayload): void => {
      callback(payload)
    }
    ipcRenderer.on('update:status', listener)
    return () => {
      ipcRenderer.removeListener('update:status', listener)
    }
  }
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-expect-error (define in dts)
  window.api = api
}
