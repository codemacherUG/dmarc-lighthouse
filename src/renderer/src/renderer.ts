import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart,
  DoughnutController,
  BarController,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
  Filler
} from 'chart.js'
import { analyzeFromReports, applyDashboardFilter } from '../../shared/analyze'
import type {
  AlignmentBreakdown,
  AnalyzeProgress,
  AnalyzeResult,
  DateRangePreset,
  ImapConnectionInput,
  NamedBucket,
  ProviderPreset,
  ReportRow,
  SavedSettingsPublic,
  UpdateStatusPayload
} from '../../shared/types'
import { PROVIDER_PRESETS } from '../../shared/types'

Chart.register(
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  DoughnutController,
  BarController,
  LineController,
  LineElement,
  PointElement,
  Legend,
  Tooltip,
  Filler
)

const PASS = '#1f7a45'
const FAIL = '#b33a2b'
const OTHER = '#8a93a3'
const VOLUME_PASS = 'rgba(31, 122, 69, 0.85)'
const VOLUME_FAIL = 'rgba(179, 58, 43, 0.8)'
const RATE_LINE = '#1f6f8b'

const statusEl = document.getElementById('status') as HTMLDivElement
const progressEl = document.getElementById('progress') as HTMLProgressElement
const progressLabelEl = document.getElementById('progress-label') as HTMLSpanElement
const accountLabelEl = document.getElementById('account-label') as HTMLSpanElement
const reportsBody = document.getElementById('reports-body') as HTMLTableSectionElement
const detailEl = document.getElementById('detail') as HTMLDivElement
const tableOrgs = document.getElementById('table-orgs') as HTMLTableSectionElement
const tableIps = document.getElementById('table-ips') as HTMLTableSectionElement
const tableFrom = document.getElementById('table-from') as HTMLTableSectionElement
const dropOverlay = document.getElementById('drop-overlay') as HTMLDivElement
const filterRangeEl = document.getElementById('filter-range') as HTMLSelectElement
const filterDomainEl = document.getElementById('filter-domain') as HTMLSelectElement
const dnsDomainEl = document.getElementById('dns-domain') as HTMLInputElement
const dnsResultEl = document.getElementById('dns-result') as HTMLDivElement

const btnSettings = document.getElementById('btn-settings') as HTMLButtonElement
const btnInfo = document.getElementById('btn-info') as HTMLButtonElement
const btnFetch = document.getElementById('btn-fetch') as HTMLButtonElement
const btnOpenFiles = document.getElementById('btn-open-files') as HTMLButtonElement
const btnExport = document.getElementById('btn-export') as HTMLButtonElement
const btnDns = document.getElementById('btn-dns') as HTMLButtonElement
const settingsDialog = document.getElementById('settings-dialog') as HTMLDialogElement
const infoDialog = document.getElementById('info-dialog') as HTMLDialogElement
const exportDialog = document.getElementById('export-dialog') as HTMLDialogElement
const settingsForm = document.getElementById('settings-form') as HTMLFormElement
const btnCloseSettings = document.getElementById('btn-close-settings') as HTMLButtonElement
const btnCloseInfo = document.getElementById('btn-close-info') as HTMLButtonElement
const btnCloseExport = document.getElementById('btn-close-export') as HTMLButtonElement
const btnInfoOk = document.getElementById('btn-info-ok') as HTMLButtonElement
const btnCheckUpdate = document.getElementById('btn-check-update') as HTMLButtonElement
const btnTest = document.getElementById('btn-test') as HTMLButtonElement
const btnClearCache = document.getElementById('btn-clear-cache') as HTMLButtonElement
const btnExportCsv = document.getElementById('btn-export-csv') as HTMLButtonElement
const btnExportJson = document.getElementById('btn-export-json') as HTMLButtonElement
const passwordHintEl = document.getElementById('password-hint') as HTMLParagraphElement
const settingsStatusEl = document.getElementById('settings-status') as HTMLParagraphElement
const aboutVersionEl = document.getElementById('about-version') as HTMLSpanElement
const updateCheckStatusEl = document.getElementById('update-check-status') as HTMLParagraphElement
const updateBanner = document.getElementById('update-banner') as HTMLDivElement
const updateBannerText = document.getElementById('update-banner-text') as HTMLSpanElement
const btnUpdateInstall = document.getElementById('btn-update-install') as HTMLButtonElement
const btnUpdateDismiss = document.getElementById('btn-update-dismiss') as HTMLButtonElement

const providerEl = document.getElementById('provider') as HTMLSelectElement
const hostEl = document.getElementById('host') as HTMLInputElement
const portEl = document.getElementById('port') as HTMLInputElement
const secureEl = document.getElementById('secure') as HTMLInputElement
const userEl = document.getElementById('user') as HTMLInputElement
const passwordEl = document.getElementById('password') as HTMLInputElement
const mailboxEl = document.getElementById('mailbox') as HTMLInputElement
const subjectFilterEl = document.getElementById('subjectFilter') as HTMLInputElement
const autoFetchMinutesEl = document.getElementById('autoFetchMinutes') as HTMLInputElement
const notifyOnFailEl = document.getElementById('notifyOnFail') as HTMLInputElement
const markSeenAfterFetchEl = document.getElementById('markSeenAfterFetch') as HTMLInputElement

let selectedReportId: string | null = null
let busy = false
let savedSettings: SavedSettingsPublic | null = null
let fullResult: AnalyzeResult | null = null
let viewResult: AnalyzeResult | null = null
const ipLabelCache = new Map<string, { ptr: string | null; provider: string | null }>()

const chartDmarc = createDoughnut('chart-dmarc')
const chartSpf = createDoughnut('chart-spf')
const chartDkim = createDoughnut('chart-dkim')
const chartVolume = new Chart(document.getElementById('chart-volume') as HTMLCanvasElement, {
  data: {
    labels: [] as string[],
    datasets: [
      {
        type: 'bar',
        label: 'Pass',
        data: [] as number[],
        backgroundColor: VOLUME_PASS,
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'bar',
        label: 'Fail',
        data: [] as number[],
        backgroundColor: VOLUME_FAIL,
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'line',
        label: 'Pass-Rate %',
        data: [] as number[],
        borderColor: RATE_LINE,
        backgroundColor: 'rgba(31, 111, 139, 0.12)',
        tension: 0.25,
        fill: false,
        yAxisID: 'y1',
        pointRadius: 2,
        borderWidth: 2
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: { stacked: true, grid: { display: false } },
      y: { stacked: true, beginAtZero: true, position: 'left' },
      y1: {
        beginAtZero: true,
        max: 100,
        position: 'right',
        grid: { drawOnChartArea: false },
        ticks: { callback: (v) => `${v}%` }
      }
    },
    plugins: {
      legend: { position: 'bottom' }
    }
  }
})

function createDoughnut(id: string): Chart<'doughnut'> {
  return new Chart(document.getElementById(id) as HTMLCanvasElement, {
    type: 'doughnut',
    data: {
      labels: ['Pass', 'Fail', 'Sonstige'],
      datasets: [
        {
          data: [0, 0, 0],
          backgroundColor: [PASS, FAIL, OTHER],
          borderWidth: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom' }
      }
    }
  })
}

function setStatus(message: string, kind: 'ok' | 'error' | '' = ''): void {
  statusEl.textContent = message
  statusEl.classList.remove('ok', 'error')
  if (kind) statusEl.classList.add(kind)
}

function showUpdateBanner(text: string, showInstall: boolean): void {
  updateBannerText.textContent = text
  updateBanner.classList.remove('hidden', 'error', 'ready')
  if (showInstall) updateBanner.classList.add('ready')
  btnUpdateInstall.classList.toggle('hidden', !showInstall)
}

function hideUpdateBanner(): void {
  updateBanner.classList.add('hidden')
  btnUpdateInstall.classList.add('hidden')
}

function applyUpdateStatus(payload: UpdateStatusPayload): void {
  switch (payload.status) {
    case 'checking':
      updateCheckStatusEl.textContent = 'Prüfe auf Updates…'
      break
    case 'available':
      showUpdateBanner(`Update ${payload.version} verfügbar — Download startet…`, false)
      updateCheckStatusEl.textContent = `Update ${payload.version} verfügbar.`
      break
    case 'downloading': {
      const pct = Math.max(0, Math.min(100, Math.round(payload.percent)))
      showUpdateBanner(`Update wird heruntergeladen… ${pct}%`, false)
      updateCheckStatusEl.textContent = `Download: ${pct}%`
      break
    }
    case 'downloaded':
      showUpdateBanner(`Update ${payload.version} bereit. Neu starten, um zu installieren.`, true)
      updateCheckStatusEl.textContent = `Update ${payload.version} heruntergeladen.`
      break
    case 'not-available':
      updateCheckStatusEl.textContent = payload.version
        ? `Keine neueren Updates (aktuell ${payload.version}).`
        : 'Keine neueren Updates.'
      break
    case 'error':
      updateBannerText.textContent = `Update-Fehler: ${payload.message}`
      updateBanner.classList.remove('hidden', 'ready')
      updateBanner.classList.add('error')
      btnUpdateInstall.classList.add('hidden')
      updateCheckStatusEl.textContent = payload.message
      break
  }
}

function setBusy(next: boolean): void {
  busy = next
  btnFetch.disabled = next
  btnSettings.disabled = next
  btnTest.disabled = next
  btnOpenFiles.disabled = next
  btnDns.disabled = next
}

function readSettingsForm(): ImapConnectionInput {
  return {
    provider: providerEl.value as ProviderPreset,
    host: hostEl.value.trim(),
    port: Number(portEl.value) || 993,
    secure: secureEl.checked,
    user: userEl.value.trim(),
    password: passwordEl.value,
    mailbox: mailboxEl.value.trim() || 'INBOX',
    subjectFilter: subjectFilterEl.value,
    autoFetchMinutes: Number(autoFetchMinutesEl.value) || 0,
    notifyOnFail: notifyOnFailEl.checked,
    markSeenAfterFetch: markSeenAfterFetchEl.checked
  }
}

function applyProviderPreset(provider: ProviderPreset): void {
  const preset = PROVIDER_PRESETS[provider]
  if (provider !== 'custom') {
    hostEl.value = preset.host
  }
  portEl.value = String(preset.port)
  secureEl.checked = preset.secure
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString('de-DE')
}

function formatRange(begin: string | null, end: string | null): string {
  return `${formatDate(begin)} – ${formatDate(end)}`
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function updateAccountLabel(settings: SavedSettingsPublic): void {
  if (!settings.user) {
    accountLabelEl.textContent = 'Keine Zugangsdaten'
    return
  }
  const host = settings.host || PROVIDER_PRESETS[settings.provider].host || 'IMAP'
  accountLabelEl.textContent = `${settings.user} @ ${host}`
}

function updateSummary(result: AnalyzeResult | null): void {
  const map: Record<string, string> = {
    reportCount: result ? String(result.aggregate.reportCount) : '—',
    total: result ? String(result.aggregate.total) : '—',
    passing: result ? String(result.aggregate.passing) : '—',
    failing: result ? String(result.aggregate.failing) : '—',
    passRate: result ? `${result.aggregate.passRate.toFixed(1)}%` : '—',
    range: result ? formatRange(result.aggregate.dateBegin, result.aggregate.dateEnd) : '—'
  }
  for (const [key, value] of Object.entries(map)) {
    const el = document.querySelector<HTMLElement>(`[data-key="${key}"]`)
    if (el) el.textContent = value
  }
}

function setAlignmentChart(chart: Chart<'doughnut'>, data: AlignmentBreakdown): void {
  chart.data.datasets[0].data = [data.pass, data.fail, data.other]
  chart.update()
}

function renderBucketTable(
  tbody: HTMLTableSectionElement,
  rows: NamedBucket[],
  withIpMeta = false
): void {
  if (!rows.length) {
    tbody.innerHTML = '<tr class="empty"><td colspan="3">Keine Daten</td></tr>'
    return
  }
  tbody.innerHTML = rows
    .map((r) => {
      let nameHtml = `<span class="mono">${escapeHtml(r.name)}</span>`
      if (withIpMeta) {
        const meta = ipLabelCache.get(r.name)
        const provider = r.provider ?? meta?.provider
        const ptr = r.label ?? meta?.ptr
        const bits: string[] = []
        if (provider) bits.push(`<span class="badge">${escapeHtml(provider)}</span>`)
        if (ptr) bits.push(`<span class="ptr">${escapeHtml(ptr)}</span>`)
        if (bits.length) nameHtml += `<div class="ip-meta">${bits.join(' ')}</div>`
      }
      return `
      <tr>
        <td>${nameHtml}</td>
        <td>${r.count}</td>
        <td>
          <span class="rate-bar"><span style="width:${Math.min(100, r.passRate)}%"></span></span>
          ${r.passRate.toFixed(1)}%
        </td>
      </tr>`
    })
    .join('')
}

function renderDashboard(result: AnalyzeResult | null): void {
  if (!result) {
    setAlignmentChart(chartDmarc, { pass: 0, fail: 0, other: 0 })
    setAlignmentChart(chartSpf, { pass: 0, fail: 0, other: 0 })
    setAlignmentChart(chartDkim, { pass: 0, fail: 0, other: 0 })
    chartVolume.data.labels = []
    chartVolume.data.datasets[0].data = []
    chartVolume.data.datasets[1].data = []
    chartVolume.data.datasets[2].data = []
    chartVolume.update()
    renderBucketTable(tableOrgs, [])
    renderBucketTable(tableIps, [])
    renderBucketTable(tableFrom, [])
    return
  }

  const d = result.dashboard
  setAlignmentChart(chartDmarc, d.dmarc)
  setAlignmentChart(chartSpf, d.spf)
  setAlignmentChart(chartDkim, d.dkim)

  chartVolume.data.labels = d.volumeByDay.map((p) => p.date)
  chartVolume.data.datasets[0].data = d.volumeByDay.map((p) => p.passing)
  chartVolume.data.datasets[1].data = d.volumeByDay.map((p) => p.failing)
  chartVolume.data.datasets[2].data = d.volumeByDay.map((p) => p.passRate)
  chartVolume.update()

  renderBucketTable(tableOrgs, d.byOrg)
  renderBucketTable(tableIps, d.bySourceIp, true)
  renderBucketTable(tableFrom, d.byHeaderFrom)

  void enrichIpLabels(d.bySourceIp.map((r) => r.name))
}

async function enrichIpLabels(ips: string[]): Promise<void> {
  const missing = ips.filter((ip) => !ipLabelCache.has(ip)).slice(0, 40)
  if (!missing.length) return
  try {
    const infos = await window.api.resolveIps(missing)
    for (const info of infos) {
      ipLabelCache.set(info.ip, { ptr: info.ptr, provider: info.provider })
    }
    if (viewResult) {
      renderBucketTable(tableIps, viewResult.dashboard.bySourceIp, true)
    }
  } catch {
    // Reverse-DNS ist optional.
  }
}

function renderDetail(report: ReportRow | null): void {
  if (!report) {
    detailEl.innerHTML = '<p class="muted">Report in der Tabelle auswählen.</p>'
    return
  }

  const rows = report.records
    .map((r) => {
      const reasons =
        r.reasons?.length > 0
          ? r.reasons
              .map((x) => escapeHtml([x.type, x.comment].filter(Boolean).join(': ')))
              .join('<br />')
          : '—'
      return `
      <tr>
        <td class="mono">${escapeHtml(r.sourceIp)}</td>
        <td>${r.count}</td>
        <td>${escapeHtml(r.disposition ?? '—')}</td>
        <td class="${r.dkimResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.dkimResult ?? '—')}</td>
        <td class="${r.spfResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.spfResult ?? '—')}</td>
        <td class="${r.passesDmarc ? 'pass' : 'fail'}">${r.passesDmarc ? 'pass' : 'fail'}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
        <td class="reasons">${reasons}</td>
      </tr>`
    })
    .join('')

  detailEl.innerHTML = `
    <h3>${escapeHtml(report.orgName)} → ${escapeHtml(report.domain)}</h3>
    <div class="meta">
      ID: <span class="mono">${escapeHtml(report.reportId)}</span><br />
      Zeitraum: ${escapeHtml(formatRange(report.dateBegin, report.dateEnd))}<br />
      Policy: ${escapeHtml(report.policyP ?? '—')} ·
      ${report.passing}/${report.total} pass (${report.passRate.toFixed(1)}%)
    </div>
    <table>
      <thead>
        <tr>
          <th>IP</th>
          <th>Count</th>
          <th>Disp.</th>
          <th>DKIM</th>
          <th>SPF</th>
          <th>DMARC</th>
          <th>From</th>
          <th>Reasons</th>
        </tr>
      </thead>
      <tbody>${rows || '<tr><td colspan="8">Keine Records</td></tr>'}</tbody>
    </table>
  `
}

function renderReports(result: AnalyzeResult | null): void {
  reportsBody.innerHTML = ''
  if (!result || result.reports.length === 0) {
    reportsBody.innerHTML =
      '<tr class="empty"><td colspan="8">Keine DMARC-Reports gefunden.</td></tr>'
    renderDetail(null)
    return
  }

  for (const report of result.reports) {
    const tr = document.createElement('tr')
    tr.dataset.reportId = report.reportId
    if (report.reportId === selectedReportId) tr.classList.add('selected')
    tr.innerHTML = `
      <td>${escapeHtml(report.orgName)}</td>
      <td>${escapeHtml(report.domain)}</td>
      <td>${escapeHtml(formatRange(report.dateBegin, report.dateEnd))}</td>
      <td>${report.total}</td>
      <td class="pass">${report.passing}</td>
      <td class="fail">${report.failing}</td>
      <td>${report.passRate.toFixed(1)}%</td>
      <td>${escapeHtml(report.policyP ?? '—')}</td>
    `
    tr.addEventListener('click', () => {
      selectedReportId = report.reportId
      for (const row of reportsBody.querySelectorAll('tr')) row.classList.remove('selected')
      tr.classList.add('selected')
      renderDetail(report)
    })
    reportsBody.appendChild(tr)
  }

  const selected =
    result.reports.find((r) => r.reportId === selectedReportId) ?? result.reports[0] ?? null
  selectedReportId = selected?.reportId ?? null
  if (selected) {
    const row = reportsBody.querySelector(`tr[data-report-id="${CSS.escape(selected.reportId)}"]`)
    row?.classList.add('selected')
  }
  renderDetail(selected)
}

function fillDomainFilter(result: AnalyzeResult | null): void {
  const current = filterDomainEl.value
  const domains = result?.aggregate.domains ?? []
  filterDomainEl.innerHTML =
    '<option value="">Alle Domains</option>' +
    domains.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('')
  if (domains.includes(current)) filterDomainEl.value = current
  if (domains.length === 1 && !dnsDomainEl.value) {
    dnsDomainEl.value = domains[0]
  }
}

function applyView(): void {
  if (!fullResult) {
    viewResult = null
    updateSummary(null)
    renderDashboard(null)
    renderReports(null)
    btnExport.disabled = true
    return
  }

  viewResult = applyDashboardFilter(fullResult, {
    range: filterRangeEl.value as DateRangePreset,
    domain: filterDomainEl.value
  })
  updateSummary(viewResult)
  renderDashboard(viewResult)
  renderReports(viewResult)
  btnExport.disabled = viewResult.reports.length === 0
}

function showResult(result: AnalyzeResult, statusMessage?: string): void {
  fullResult = result
  fillDomainFilter(result)
  applyView()
  if (statusMessage) {
    setStatus(statusMessage, 'ok')
  } else {
    const skippedNote = result.skipped ? `, ${result.skipped} übersprungen` : ''
    const newNote = result.newReports != null ? `, ${result.newReports} neu` : ''
    const cacheNote = result.fromCache ? ' (inkl. Cache)' : ''
    setStatus(
      `${result.aggregate.reportCount} Reports${newNote}${cacheNote} (${result.aggregate.total} Nachrichten${skippedNote}).`,
      'ok'
    )
  }
}

function applyProgress(progress: AnalyzeProgress): void {
  const pct =
    progress.total > 0 ? Math.min(100, Math.round((progress.processed / progress.total) * 100)) : 0
  progressEl.value = progress.phase === 'done' ? 100 : pct
  progressLabelEl.textContent = progress.message ?? progress.phase
  if (progress.phase === 'error') {
    setStatus(progress.message ?? 'Fehler', 'error')
  } else if (progress.message) {
    setStatus(progress.message)
  }
}

function fillSettingsForm(settings: SavedSettingsPublic): void {
  providerEl.value = settings.provider
  hostEl.value = settings.host
  portEl.value = String(settings.port)
  secureEl.checked = settings.secure
  userEl.value = settings.user
  mailboxEl.value = settings.mailbox
  subjectFilterEl.value = settings.subjectFilter
  autoFetchMinutesEl.value = String(settings.autoFetchMinutes ?? 0)
  notifyOnFailEl.checked = settings.notifyOnFail !== false
  markSeenAfterFetchEl.checked = Boolean(settings.markSeenAfterFetch)
  passwordEl.value = ''
  passwordHintEl.textContent = settings.hasPassword
    ? 'Ein Passwort ist verschlüsselt gespeichert. Feld leer lassen, um es beizubehalten.'
    : 'Gmail/Outlook: App-Passwort verwenden (nicht das normale Kontopasswort).'
  settingsStatusEl.textContent = ''
}

async function loadSettings(): Promise<void> {
  savedSettings = await window.api.loadSettings()
  fillSettingsForm(savedSettings)
  updateAccountLabel(savedSettings)
  if (!savedSettings.hasPassword || !savedSettings.user) {
    setStatus('Bitte zuerst IMAP-Zugangsdaten speichern — oder Dateien per Drag & Drop laden.')
  }
}

function openSettings(): void {
  if (savedSettings) fillSettingsForm(savedSettings)
  settingsDialog.showModal()
}

btnSettings.addEventListener('click', () => openSettings())
btnCloseSettings.addEventListener('click', () => settingsDialog.close())
btnInfo.addEventListener('click', () => {
  updateCheckStatusEl.textContent = ''
  infoDialog.showModal()
})
btnCloseInfo.addEventListener('click', () => infoDialog.close())
btnInfoOk.addEventListener('click', () => infoDialog.close())
btnExport.addEventListener('click', () => exportDialog.showModal())
btnCloseExport.addEventListener('click', () => exportDialog.close())

btnCheckUpdate.addEventListener('click', async () => {
  updateCheckStatusEl.textContent = 'Prüfe auf Updates…'
  try {
    const result = await window.api.checkForUpdates()
    if (!result.ok) updateCheckStatusEl.textContent = result.message
  } catch (err) {
    updateCheckStatusEl.textContent = err instanceof Error ? err.message : String(err)
  }
})

btnUpdateInstall.addEventListener('click', () => {
  void window.api.installUpdate()
})

btnUpdateDismiss.addEventListener('click', () => hideUpdateBanner())

providerEl.addEventListener('change', () => {
  applyProviderPreset(providerEl.value as ProviderPreset)
})

filterRangeEl.addEventListener('change', () => applyView())
filterDomainEl.addEventListener('change', () => applyView())

btnTest.addEventListener('click', async () => {
  if (busy) return
  setBusy(true)
  settingsStatusEl.textContent = 'Teste Verbindung…'
  try {
    const result = await window.api.testConnection(readSettingsForm())
    settingsStatusEl.textContent = result.message
    setStatus(result.message, result.ok ? 'ok' : 'error')
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    settingsStatusEl.textContent = msg
    setStatus(msg, 'error')
  } finally {
    setBusy(false)
  }
})

btnClearCache.addEventListener('click', async () => {
  if (busy) return
  setBusy(true)
  try {
    const result = await window.api.clearCache()
    settingsStatusEl.textContent = result.message
    if (result.ok) {
      fullResult = null
      applyView()
      setStatus('Cache geleert. Nächster Abruf holt alle Nachrichten erneut.', 'ok')
    }
  } catch (err) {
    settingsStatusEl.textContent = err instanceof Error ? err.message : String(err)
  } finally {
    setBusy(false)
  }
})

settingsForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  if (busy) return
  setBusy(true)
  try {
    savedSettings = await window.api.saveSettings(readSettingsForm())
    passwordEl.value = ''
    fillSettingsForm(savedSettings)
    updateAccountLabel(savedSettings)
    settingsStatusEl.textContent = 'Zugangsdaten gespeichert.'
    setStatus('Einstellungen gespeichert.', 'ok')
    settingsDialog.close()
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    settingsStatusEl.textContent = msg
    setStatus(msg, 'error')
  } finally {
    setBusy(false)
  }
})

btnFetch.addEventListener('click', async () => {
  if (busy) return
  if (!savedSettings?.hasPassword || !savedSettings.user) {
    openSettings()
    settingsStatusEl.textContent = 'Bitte Zugangsdaten speichern, bevor Reports abgerufen werden.'
    return
  }

  setBusy(true)
  setStatus('Starte Abruf…')
  progressEl.value = 0
  progressLabelEl.textContent = ''
  try {
    const result = await window.api.fetchSaved()
    selectedReportId = null
    showResult(result)
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    setBusy(false)
  }
})

btnOpenFiles.addEventListener('click', async () => {
  if (busy) return
  setBusy(true)
  try {
    const result = await window.api.openFiles()
    if (!result) return
    selectedReportId = null
    if (fullResult) {
      const map = new Map(fullResult.reports.map((r) => [r.reportId, r]))
      for (const r of result.reports) {
        map.set(r.reportId || `${r.orgName}|${r.domain}|${r.dateEnd}`, r)
      }
      showResult(
        analyzeFromReports([...map.values()], {
          skipped: fullResult.skipped + result.skipped,
          errors: [...fullResult.errors, ...result.errors].slice(0, 50),
          newReports: result.reports.length
        }),
        `${result.reports.length} lokale Reports geladen.`
      )
    } else {
      showResult(result, `${result.reports.length} lokale Reports geladen.`)
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
    dnsResultEl.textContent = 'Bitte eine Domain eingeben.'
    dnsResultEl.className = 'dns-result error'
    return
  }
  dnsResultEl.textContent = `Prüfe DNS für ${domain}…`
  dnsResultEl.className = 'dns-result'
  try {
    const result = await window.api.checkDns(domain)
    const dmarcLine = result.dmarc.found
      ? `DMARC: p=${result.dmarc.policy ?? '?'} · rua=${result.dmarc.rua ?? '—'}`
      : `DMARC: nicht gefunden${result.dmarc.error ? ` (${result.dmarc.error})` : ''}`
    const spfLine = result.spf.found
      ? `SPF: ${result.spf.records[0]}`
      : `SPF: nicht gefunden${result.spf.error ? ` (${result.spf.error})` : ''}`
    dnsResultEl.innerHTML = `<strong>${escapeHtml(result.domain)}</strong><br />${escapeHtml(dmarcLine)}<br /><span class="mono">${escapeHtml(spfLine)}</span>`
    dnsResultEl.className = 'dns-result ok'
  } catch (err) {
    dnsResultEl.textContent = err instanceof Error ? err.message : String(err)
    dnsResultEl.className = 'dns-result error'
  }
})

async function doExport(format: 'json' | 'csv'): Promise<void> {
  if (!viewResult) return
  try {
    const res = await window.api.exportSave(viewResult, format)
    setStatus(res.message, res.ok ? 'ok' : '')
    if (res.ok) exportDialog.close()
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  }
}

btnExportCsv.addEventListener('click', () => void doExport('csv'))
btnExportJson.addEventListener('click', () => void doExport('json'))

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
  if (!files.length || busy) return
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
    setStatus('Dateien konnten nicht gelesen werden.', 'error')
    return
  }
  void (async () => {
    setBusy(true)
    try {
      const result = await window.api.parsePaths(paths)
      selectedReportId = null
      showResult(result, `${result.reports.length} Dateien geladen.`)
    } catch (err) {
      setStatus(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setBusy(false)
    }
  })()
})

window.api.onProgress(applyProgress)
window.api.onResult((result) => {
  selectedReportId = null
  showResult(result)
})
window.api.onUpdateStatus(applyUpdateStatus)

void (async () => {
  try {
    aboutVersionEl.textContent = await window.api.getAppVersion()
    await loadSettings()
    const cached = await window.api.loadCache()
    if (cached && cached.reports.length > 0) {
      showResult(cached, `${cached.aggregate.reportCount} Reports aus Cache — Abruf holt nur Neue.`)
    }
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  }
})()
