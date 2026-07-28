import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart,
  DoughnutController,
  BarController,
  Legend,
  LinearScale,
  Tooltip
} from 'chart.js'
import type {
  AlignmentBreakdown,
  AnalyzeProgress,
  AnalyzeResult,
  ImapConnectionInput,
  NamedBucket,
  ProviderPreset,
  ReportRow,
  SavedSettingsPublic
} from '../../shared/types'
import { PROVIDER_PRESETS } from '../../shared/types'

Chart.register(
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  DoughnutController,
  BarController,
  Legend,
  Tooltip
)

const PASS = '#1f7a45'
const FAIL = '#b33a2b'
const OTHER = '#8a93a3'
const VOLUME_PASS = 'rgba(31, 122, 69, 0.85)'
const VOLUME_FAIL = 'rgba(179, 58, 43, 0.8)'

const statusEl = document.getElementById('status') as HTMLDivElement
const progressEl = document.getElementById('progress') as HTMLProgressElement
const progressLabelEl = document.getElementById('progress-label') as HTMLSpanElement
const accountLabelEl = document.getElementById('account-label') as HTMLSpanElement
const reportsBody = document.getElementById('reports-body') as HTMLTableSectionElement
const detailEl = document.getElementById('detail') as HTMLDivElement
const tableOrgs = document.getElementById('table-orgs') as HTMLTableSectionElement
const tableIps = document.getElementById('table-ips') as HTMLTableSectionElement
const tableFrom = document.getElementById('table-from') as HTMLTableSectionElement

const btnSettings = document.getElementById('btn-settings') as HTMLButtonElement
const btnInfo = document.getElementById('btn-info') as HTMLButtonElement
const btnFetch = document.getElementById('btn-fetch') as HTMLButtonElement
const settingsDialog = document.getElementById('settings-dialog') as HTMLDialogElement
const infoDialog = document.getElementById('info-dialog') as HTMLDialogElement
const settingsForm = document.getElementById('settings-form') as HTMLFormElement
const btnCloseSettings = document.getElementById('btn-close-settings') as HTMLButtonElement
const btnCloseInfo = document.getElementById('btn-close-info') as HTMLButtonElement
const btnInfoOk = document.getElementById('btn-info-ok') as HTMLButtonElement
const btnTest = document.getElementById('btn-test') as HTMLButtonElement
const passwordHintEl = document.getElementById('password-hint') as HTMLParagraphElement
const settingsStatusEl = document.getElementById('settings-status') as HTMLParagraphElement

const providerEl = document.getElementById('provider') as HTMLSelectElement
const hostEl = document.getElementById('host') as HTMLInputElement
const portEl = document.getElementById('port') as HTMLInputElement
const secureEl = document.getElementById('secure') as HTMLInputElement
const userEl = document.getElementById('user') as HTMLInputElement
const passwordEl = document.getElementById('password') as HTMLInputElement
const mailboxEl = document.getElementById('mailbox') as HTMLInputElement
const subjectFilterEl = document.getElementById('subjectFilter') as HTMLInputElement

let selectedReportId: string | null = null
let busy = false
let savedSettings: SavedSettingsPublic | null = null

const chartDmarc = createDoughnut('chart-dmarc')
const chartSpf = createDoughnut('chart-spf')
const chartDkim = createDoughnut('chart-dkim')
const chartVolume = new Chart<'bar'>(document.getElementById('chart-volume') as HTMLCanvasElement, {
  type: 'bar',
  data: {
    labels: [] as string[],
    datasets: [
      {
        label: 'Pass',
        data: [] as number[],
        backgroundColor: VOLUME_PASS,
        stack: 'v'
      },
      {
        label: 'Fail',
        data: [] as number[],
        backgroundColor: VOLUME_FAIL,
        stack: 'v'
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { stacked: true, grid: { display: false } },
      y: { stacked: true, beginAtZero: true }
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

function setBusy(next: boolean): void {
  busy = next
  btnFetch.disabled = next
  btnSettings.disabled = next
  btnTest.disabled = next
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
    subjectFilter: subjectFilterEl.value
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
    range: result
      ? formatRange(result.aggregate.dateBegin, result.aggregate.dateEnd)
      : '—'
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

function renderBucketTable(tbody: HTMLTableSectionElement, rows: NamedBucket[]): void {
  if (!rows.length) {
    tbody.innerHTML = '<tr class="empty"><td colspan="3">Keine Daten</td></tr>'
    return
  }
  tbody.innerHTML = rows
    .map(
      (r) => `
      <tr>
        <td class="mono">${escapeHtml(r.name)}</td>
        <td>${r.count}</td>
        <td>
          <span class="rate-bar"><span style="width:${Math.min(100, r.passRate)}%"></span></span>
          ${r.passRate.toFixed(1)}%
        </td>
      </tr>`
    )
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
  chartVolume.update()

  renderBucketTable(tableOrgs, d.byOrg)
  renderBucketTable(tableIps, d.bySourceIp)
  renderBucketTable(tableFrom, d.byHeaderFrom)
}

function renderDetail(report: ReportRow | null): void {
  if (!report) {
    detailEl.innerHTML = '<p class="muted">Report in der Tabelle auswählen.</p>'
    return
  }

  const rows = report.records
    .map(
      (r) => `
      <tr>
        <td class="mono">${escapeHtml(r.sourceIp)}</td>
        <td>${r.count}</td>
        <td>${escapeHtml(r.disposition ?? '—')}</td>
        <td class="${r.dkimResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.dkimResult ?? '—')}</td>
        <td class="${r.spfResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.spfResult ?? '—')}</td>
        <td class="${r.passesDmarc ? 'pass' : 'fail'}">${r.passesDmarc ? 'pass' : 'fail'}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
      </tr>`
    )
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
        </tr>
      </thead>
      <tbody>${rows || '<tr><td colspan="7">Keine Records</td></tr>'}</tbody>
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
    setStatus('Bitte zuerst IMAP-Zugangsdaten in den Einstellungen speichern.')
  }
}

function openSettings(): void {
  if (savedSettings) fillSettingsForm(savedSettings)
  settingsDialog.showModal()
}

btnSettings.addEventListener('click', () => openSettings())
btnCloseSettings.addEventListener('click', () => settingsDialog.close())

btnInfo.addEventListener('click', () => infoDialog.showModal())
btnCloseInfo.addEventListener('click', () => infoDialog.close())
btnInfoOk.addEventListener('click', () => infoDialog.close())

providerEl.addEventListener('change', () => {
  applyProviderPreset(providerEl.value as ProviderPreset)
})

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
    updateSummary(result)
    renderDashboard(result)
    renderReports(result)
    const skippedNote = result.skipped ? `, ${result.skipped} übersprungen` : ''
    setStatus(
      `${result.aggregate.reportCount} Reports analysiert (${result.aggregate.total} Nachrichten${skippedNote}).`,
      'ok'
    )
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    setBusy(false)
  }
})

window.api.onProgress(applyProgress)

void loadSettings().catch((err) => {
  setStatus(err instanceof Error ? err.message : String(err), 'error')
})
