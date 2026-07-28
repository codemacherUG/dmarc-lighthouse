import { contextBridge, ipcRenderer, webUtils, type IpcRendererEvent } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'
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

const api = {
  loadSettings: (): Promise<SavedSettingsPublic> => ipcRenderer.invoke('settings:load'),
  saveSettings: (input: ImapConnectionInput): Promise<SavedSettingsPublic> =>
    ipcRenderer.invoke('settings:save', input),
  testConnection: (input: ImapConnectionInput): Promise<TestConnectionResult> =>
    ipcRenderer.invoke('imap:test', input),
  fetchAndAnalyze: (input: ImapConnectionInput): Promise<AnalyzeResult> =>
    ipcRenderer.invoke('imap:fetchAndAnalyze', input),
  fetchSaved: (): Promise<AnalyzeResult> => ipcRenderer.invoke('imap:fetchSaved'),
  loadCache: (): Promise<AnalyzeResult | null> => ipcRenderer.invoke('cache:load'),
  clearCache: (): Promise<{ ok: boolean; message: string }> => ipcRenderer.invoke('cache:clear'),
  resolveIps: (ips: string[]): Promise<IpInfo[]> => ipcRenderer.invoke('ip:resolve', ips),
  checkDns: (domain: string): Promise<DnsCheckResult> => ipcRenderer.invoke('dns:check', domain),
  openFiles: (): Promise<AnalyzeResult | null> => ipcRenderer.invoke('files:open'),
  parsePaths: (paths: string[]): Promise<AnalyzeResult> =>
    ipcRenderer.invoke('files:parsePaths', paths),
  getPathForFile: (file: File): string => webUtils.getPathForFile(file),
  exportSave: (
    result: AnalyzeResult,
    format: 'json' | 'csv'
  ): Promise<{ ok: boolean; message: string }> => ipcRenderer.invoke('export:save', result, format),
  getAppVersion: (): Promise<string> => ipcRenderer.invoke('app:getVersion'),
  checkForUpdates: (): Promise<{ ok: boolean; message: string }> =>
    ipcRenderer.invoke('update:check'),
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
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-expect-error (define in dts)
  window.electron = electronAPI
  // @ts-expect-error (define in dts)
  window.api = api
}
