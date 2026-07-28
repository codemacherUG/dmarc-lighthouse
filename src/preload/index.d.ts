import { ElectronAPI } from '@electron-toolkit/preload'
import type {
  AnalyzeProgress,
  AnalyzeResult,
  DnsCheckResult,
  ImapConnectionInput,
  IpInfo,
  SavedSettingsPublic,
  TestConnectionResult,
  UpdateStatusPayload
} from '../shared/types'

export interface DmarcViewerApi {
  loadSettings: () => Promise<SavedSettingsPublic>
  saveSettings: (input: ImapConnectionInput) => Promise<SavedSettingsPublic>
  testConnection: (input: ImapConnectionInput) => Promise<TestConnectionResult>
  fetchAndAnalyze: (input: ImapConnectionInput) => Promise<AnalyzeResult>
  fetchSaved: () => Promise<AnalyzeResult>
  loadCache: () => Promise<AnalyzeResult | null>
  clearCache: () => Promise<{ ok: boolean; message: string }>
  resolveIps: (ips: string[]) => Promise<IpInfo[]>
  checkDns: (domain: string) => Promise<DnsCheckResult>
  openFiles: () => Promise<AnalyzeResult | null>
  parsePaths: (paths: string[]) => Promise<AnalyzeResult>
  getPathForFile: (file: File) => string
  exportSave: (
    result: AnalyzeResult,
    format: 'json' | 'csv'
  ) => Promise<{ ok: boolean; message: string }>
  getAppVersion: () => Promise<string>
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
  }
}
