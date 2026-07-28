import { ElectronAPI } from '@electron-toolkit/preload'
import type {
  AnalyzeProgress,
  AnalyzeResult,
  ImapConnectionInput,
  SavedSettingsPublic,
  TestConnectionResult
} from '../shared/types'

export interface DmarcViewerApi {
  loadSettings: () => Promise<SavedSettingsPublic>
  saveSettings: (input: ImapConnectionInput) => Promise<SavedSettingsPublic>
  testConnection: (input: ImapConnectionInput) => Promise<TestConnectionResult>
  fetchAndAnalyze: (input: ImapConnectionInput) => Promise<AnalyzeResult>
  fetchSaved: () => Promise<AnalyzeResult>
  onProgress: (callback: (progress: AnalyzeProgress) => void) => () => void
}

declare global {
  interface Window {
    electron: ElectronAPI
    api: DmarcViewerApi
  }
}
