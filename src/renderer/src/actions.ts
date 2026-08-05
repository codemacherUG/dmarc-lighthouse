import { analyzeFromReports } from '../../shared/analyze'
import { t } from '../../shared/i18n'
import { applyProgress, setBusy, setStatus, setTopProgress } from './chrome'
import {
  accountSelectEl,
  btnCloseExport,
  btnDns,
  btnExport,
  btnExportCsv,
  btnExportJson,
  btnFetch,
  btnOpenFiles,
  dnsDomainEl,
  dnsResultEl,
  dnsSelectorsEl,
  dropOverlay,
  exportDialog,
  filterDomainEl,
  progressLabelEl,
  settingsStatusEl
} from './dom'
import { escapeHtml } from './format'
import {
  accountHasAuth,
  activeAccount,
  applySettings,
  openSettings,
  setSwitchActiveAccount
} from './settings-ui'
import { clearDrill, state } from './state'
import { applyView, showResult } from './view'

/** Copy the active account's domain into the DNS-check field after a switch. */
function syncDnsDomainFromAccount(): void {
  const domains = state.fullResult?.aggregate.domains ?? []
  if (domains.length === 0) {
    dnsDomainEl.value = ''
    return
  }
  const selected = filterDomainEl.value
  dnsDomainEl.value = selected && domains.includes(selected) ? selected : domains[0]
}

export async function switchActiveAccount(id: string): Promise<void> {
  applySettings(await window.api.setActiveAccount(id))
  state.selectedReportId = null
  clearDrill()
  state.fullResult = null
  const cached = await window.api.loadCache(id)
  if (cached && cached.reports.length > 0) {
    showResult(cached, t('status.cached', { count: cached.aggregate.reportCount }))
  } else {
    applyView()
    setStatus(t('status.noCache'))
  }
  syncDnsDomainFromAccount()
}

/** Collect DKIM selectors for a domain from the loaded reports. */
function collectDkimSelectors(domain: string): string[] {
  if (!state.fullResult) return []
  const d = domain.toLowerCase()
  const selectors = new Set<string>()
  for (const report of state.fullResult.reports) {
    for (const rec of report.records) {
      if (
        report.domain.toLowerCase() === d ||
        rec.dkimDomain?.toLowerCase() === d ||
        rec.headerFrom?.toLowerCase() === d
      ) {
        for (const sel of rec.dkimSelectors ?? []) selectors.add(sel)
      }
    }
  }
  return [...selectors].sort()
}

async function doExport(format: 'json' | 'csv'): Promise<void> {
  if (!state.viewResult) return
  try {
    const res = await window.api.exportSave(state.viewResult, format)
    setStatus(res.message, res.ok ? 'ok' : '')
    if (res.ok) exportDialog.close()
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  }
}

export function initActions(): void {
  setSwitchActiveAccount(switchActiveAccount)

  accountSelectEl.addEventListener('change', () => {
    if (state.busy) return
    void switchActiveAccount(accountSelectEl.value)
  })

  btnExport.addEventListener('click', () => exportDialog.showModal())
  btnCloseExport.addEventListener('click', () => exportDialog.close())
  btnExportCsv.addEventListener('click', () => void doExport('csv'))
  btnExportJson.addEventListener('click', () => void doExport('json'))

  btnFetch.addEventListener('click', async () => {
    if (state.busy) return
    const account = activeAccount()
    if (!account || !accountHasAuth(account)) {
      openSettings()
      settingsStatusEl.textContent = t('settings.needCredentials')
      return
    }

    setBusy(true)
    setStatus(t('status.fetchStart'))
    progressLabelEl.textContent = ''
    setTopProgress(null, true)
    try {
      const result = await window.api.fetchSaved(account.id)
      state.selectedReportId = null
      showResult(result)
    } catch (err) {
      setStatus(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setBusy(false)
      setTopProgress(0, false)
      progressLabelEl.textContent = ''
    }
  })

  btnOpenFiles.addEventListener('click', async () => {
    if (state.busy) return
    setBusy(true)
    try {
      const result = await window.api.openFiles()
      if (!result) return
      state.selectedReportId = null
      if (state.fullResult) {
        const map = new Map(state.fullResult.reports.map((r) => [r.reportId, r]))
        for (const r of result.reports) {
          map.set(r.reportId || `${r.orgName}|${r.domain}|${r.dateEnd}`, r)
        }
        const forensicMap = new Map(
          (state.fullResult.forensicReports ?? []).map((r) => [r.id, r] as const)
        )
        for (const r of result.forensicReports ?? []) forensicMap.set(r.id, r)
        showResult(
          analyzeFromReports([...map.values()], {
            skipped: state.fullResult.skipped + result.skipped,
            errors: [...state.fullResult.errors, ...result.errors].slice(0, 50),
            newReports: result.reports.length,
            newForensicReports: result.forensicReports?.length ?? 0,
            forensicReports: [...forensicMap.values()]
          }),
          t('status.localLoaded', { count: result.reports.length })
        )
      } else {
        showResult(result, t('status.localLoaded', { count: result.reports.length }))
      }
    } catch (err) {
      setStatus(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setBusy(false)
    }
  })

  btnDns.addEventListener('click', async () => {
    const domain = dnsDomainEl.value.trim() || filterDomainEl.value
    if (!domain) {
      dnsResultEl.textContent = t('dns.needDomain')
      dnsResultEl.className = 'dns-result error'
      return
    }
    const manualSelectors = dnsSelectorsEl.value
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    const selectors = manualSelectors.length > 0 ? manualSelectors : collectDkimSelectors(domain)

    dnsResultEl.textContent = t('dns.checking', { domain })
    dnsResultEl.className = 'dns-result'
    try {
      const result = await window.api.checkDns(domain, selectors)
      const dmarcLine = result.dmarc.found
        ? t('dns.dmarcFound', {
            policy: result.dmarc.policy ?? '?',
            rua: result.dmarc.rua ?? '—',
            ruf: result.dmarc.ruf ?? '—'
          })
        : `${t('dns.dmarcMissing')}${result.dmarc.error ? ` (${result.dmarc.error})` : ''}`
      const spfLine = result.spf.found
        ? t('dns.spfFound', { record: result.spf.records[0] })
        : `${t('dns.spfMissing')}${result.spf.error ? ` (${result.spf.error})` : ''}`

      let dkimHtml = ''
      if (result.dkim.selectors.length > 0) {
        dkimHtml = result.dkim.selectors
          .map((s) => {
            const stateHtml = s.found
              ? `<span class="pass">${escapeHtml(t('dns.dkimFound'))}</span>`
              : `<span class="fail">${escapeHtml(t('dns.dkimMissing'))}</span>`
            return t('dns.dkimLine', {
              selector: `<span class="mono">${escapeHtml(s.selector)}</span>`,
              state: stateHtml
            })
          })
          .join('<br />')
      } else {
        dkimHtml = escapeHtml(t('dns.dkimNone'))
      }

      dnsResultEl.innerHTML = `<strong>${escapeHtml(result.domain)}</strong><br />${escapeHtml(dmarcLine)}<br /><span class="mono">${escapeHtml(spfLine)}</span><br />${dkimHtml}`
      dnsResultEl.className = 'dns-result ok'
    } catch (err) {
      dnsResultEl.textContent = err instanceof Error ? err.message : String(err)
      dnsResultEl.className = 'dns-result error'
    }
  })

  // Drag & Drop
  let dragDepth = 0
  window.addEventListener('dragenter', (e) => {
    e.preventDefault()
    dragDepth += 1
    dropOverlay.classList.remove('hidden')
  })
  window.addEventListener('dragleave', (e) => {
    e.preventDefault()
    dragDepth = Math.max(0, dragDepth - 1)
    if (dragDepth === 0) dropOverlay.classList.add('hidden')
  })
  window.addEventListener('dragover', (e) => {
    e.preventDefault()
  })
  window.addEventListener('drop', (e) => {
    e.preventDefault()
    dragDepth = 0
    dropOverlay.classList.add('hidden')
    const files = [...(e.dataTransfer?.files ?? [])]
    if (!files.length || state.busy) return
    const paths = files
      .map((f) => {
        try {
          return window.api.getPathForFile(f)
        } catch {
          return ''
        }
      })
      .filter(Boolean)
    if (!paths.length) {
      setStatus(t('status.filesFailed'), 'error')
      return
    }
    void (async () => {
      setBusy(true)
      try {
        const result = await window.api.parsePaths(paths)
        state.selectedReportId = null
        showResult(result, t('status.filesLoaded', { count: result.reports.length }))
      } catch (err) {
        setStatus(err instanceof Error ? err.message : String(err), 'error')
      } finally {
        setBusy(false)
      }
    })()
  })

  window.api.onProgress(applyProgress)
  window.api.onResult((result) => {
    // Ergebnisse anderer Konten (Auto-Abruf) nicht über die aktive Ansicht legen.
    if (
      result.accountId &&
      state.settings?.activeAccountId &&
      result.accountId !== state.settings.activeAccountId
    ) {
      return
    }
    state.selectedReportId = null
    showResult(result)
  })
}
