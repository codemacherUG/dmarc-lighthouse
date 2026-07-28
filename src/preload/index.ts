import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'
import type {
  AnalyzeProgress,
  AnalyzeResult,
  ImapConnectionInput,
  SavedSettingsPublic,
  TestConnectionResult
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
  onProgress: (callback: (progress: AnalyzeProgress) => void): (() => void) => {
    const listener = (_event: IpcRendererEvent, progress: AnalyzeProgress): void => {
      callback(progress)
    }
    ipcRenderer.on('imap:progress', listener)
    return () => {
      ipcRenderer.removeListener('imap:progress', listener)
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
