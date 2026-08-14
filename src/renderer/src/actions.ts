import { t } from '../../shared/i18n'
import type { AnalyzeResult } from '../../shared/types'
import { applyProgress, setBusy, setStatus, setTopProgress } from './chrome'
import {
  accountSelectEl,
  btnCloseExport,
  btnDns,
  btnExport,
  btnExportCsv,
  btnExportJson,
  btnExportPdf,
  btnFetch,
  btnOpenFiles,
  dnsDomainEl,
  dnsForm,
  dnsResultEl,
  dnsSelectorsEl,
  dropOverlay,
  exportDialog,
  filterDomainEl,
  progressLabelEl,
  settingsStatusEl
} from './dom'
import { inspectDroppedFile, isEmailInspectOpen } from './email-inspect-ui'
import { escapeHtml } from './format'
import {
  accountHasAuth,
  activeAccount,
  applySettings,
  openSettings,
  setSwitchActiveAccount
} from './settings-ui'
import { clearDrill, state } from './state'
import { runTransportCheck } from './transport-view'
import { applyView, clearSpfMarks, showResult } from './view'

/** Show an import result and report how much of it was written to the cache. */
function showImportResult(result: AnalyzeResult): void {
  state.selectedReportId = null
  const summary = result.imported
  if (!summary?.persisted) {
    showResult(result, t('status.importNotStored', { count: result.reports.length }))
    setStatus(t('status.importNotStored', { count: result.reports.length }), 'error')
    return
  }
  const replacedNote = summary.updated
    ? t('status.importReplacedPart', { count: summary.updated })
    : ''
  showResult(
    result,
    t('status.imported', {
      count: summary.added,
      total: result.aggregate.reportCount,
      replacedNote
    })
  )
}

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
  clearSpfMarks()
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

/** Management PDF of the current view; rendering happens in the main process. */
async function doPdfExport(): Promise<void> {
  if (!state.viewResult) return
  setStatus(t('status.pdfBuilding'))
  btnExportPdf.disabled = true
  try {
    const domain = filterDomainEl.value.trim() || null
    const res = await window.api.exportPdfReport(state.viewResult, { domain })
    setStatus(res.message, res.ok ? 'ok' : '')
    if (res.ok) exportDialog.close()
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    btnExportPdf.disabled = false
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
  btnExportPdf.addEventListener('click', () => void doPdfExport())

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
      showImportResult(result)
    } catch (err) {
      setStatus(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setBusy(false)
    }
  })

  const runDnsCheck = async (): Promise<void> => {
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

    btnDns.disabled = true
    dnsResultEl.textContent = t('dns.checking', { domain })
    dnsResultEl.className = 'dns-result'
    const transport = runTransportCheck(domain)
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

      const bimi = result.bimi
      let bimiHtml = ''
      if (!bimi || !bimi.found) {
        const detail = bimi?.error ? ` (${bimi.error})` : ''
        bimiHtml = `<span class="fail">${escapeHtml(t('dns.bimiMissing'))}${escapeHtml(detail)}</span>`
      } else {
        bimiHtml = `<span class="pass">${escapeHtml(
          t('dns.bimiFound', {
            selector: bimi.selector,
            location: bimi.location || '—',
            authority: bimi.authority || '—'
          })
        )}</span>`
      }

      const resolverLine =
        result.resolver?.mode === 'authoritative'
          ? t('dns.resolverAuth', {
              ns: (result.resolver.nameservers ?? []).slice(0, 2).join(', ') || '—',
              zone: result.resolver.zone ?? result.domain
            })
          : t('dns.resolverRecursive')
      dnsResultEl.innerHTML = `<strong>${escapeHtml(result.domain)}</strong><br /><span class="muted">${escapeHtml(resolverLine)}</span><br />${escapeHtml(dmarcLine)}<br /><span class="mono">${escapeHtml(spfLine)}</span><br />${dkimHtml}<br />${bimiHtml}`
      dnsResultEl.className = 'dns-result ok'
    } catch (err) {
      dnsResultEl.textContent = err instanceof Error ? err.message : String(err)
      dnsResultEl.className = 'dns-result error'
    } finally {
      await transport
      btnDns.disabled = false
    }
  }

  dnsForm.addEventListener('submit', (event) => {
    event.preventDefault()
    void runDnsCheck()
  })

  // Drag & Drop
  let dragDepth = 0
  window.addEventListener('dragenter', (e) => {
    e.preventDefault()
    if (isEmailInspectOpen()) return
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
    if (isEmailInspectOpen()) {
      const file = files[0]
      if (file) void inspectDroppedFile(file)
      return
    }
    void (async () => {
      setBusy(true)
      try {
        const buffers = await Promise.all(
          files.map(async (f) => ({
            name: f.name,
            data: await f.arrayBuffer()
          }))
        )
        const result = await window.api.parseBuffers(buffers)
        showImportResult(result)
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
