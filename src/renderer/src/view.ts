import {
  applyDashboardFilter,
  buildDomainStats,
  isGoogleIpInfo,
  isGoogleNoiseAuthPattern,
  mergeDomainHealth
} from '../../shared/analyze'
import { t, type MessageKey } from '../../shared/i18n'
import type {
  AnalyzeResult,
  DateRangePreset,
  DomainHealth,
  ForensicReportRow,
  NamedBucket,
  ReportRow
} from '../../shared/types'
import {
  chartDkim,
  chartDmarc,
  chartSpf,
  clearVolumeChart,
  setAlignmentChart,
  setDispositionChart,
  setVolumeChart
} from './charts'
import { setBusy, setStatus } from './chrome'
import {
  btnCloseIpDetail,
  btnExport,
  btnIpFilter,
  btnIpRdap,
  detailEl,
  dnsDomainEl,
  domainAmpelEl,
  filterChipsEl,
  filterDomainEl,
  filterFromEl,
  filterHideGoogleNoiseEl,
  filterRangeEl,
  filterToEl,
  filterCustomWrap,
  forensicBody,
  ipDetailBody,
  ipDetailDialog,
  reportsBody,
  tableFrom,
  tableIps,
  tableOrgs
} from './dom'
import { escapeHtml, formatIpCellHtml, formatIpMetaHtml, formatRange } from './format'
import { renderIpMap, setIpMapFilterHandler } from './ip-map'
import { state, type DrillFilters } from './state'

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

function bindIpDetailButtons(root: ParentNode): void {
  for (const btn of root.querySelectorAll<HTMLButtonElement>('[data-ip-detail]')) {
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation()
      openIpDetail(btn.dataset.ipDetail ?? '')
    })
  }
}

function renderBucketTable(
  tbody: HTMLTableSectionElement,
  rows: NamedBucket[],
  options: {
    withIpMeta?: boolean
    onRowClick?: (name: string) => void
  } = {}
): void {
  if (!rows.length) {
    tbody.innerHTML = `<tr class="empty"><td colspan="3">${escapeHtml(t('table.noData'))}</td></tr>`
    return
  }
  tbody.innerHTML = rows
    .map((r) => {
      if (options.withIpMeta) {
        const ipMeta = formatIpMetaHtml(r.name, r.provider, r.label)
        return `
      <tr data-name="${escapeHtml(r.name)}"${ipMeta ? ' class="has-ip-meta"' : ''}${options.onRowClick ? ` title="${escapeHtml(t('filter.clickToFilter'))}"` : ''}>
        <td class="ip-col">${formatIpCellHtml(r.name, r.provider, r.label, { includeMeta: false })}</td>
        <td>${r.count}</td>
        <td>
          <span class="rate-bar"><span style="width:${Math.min(100, r.passRate)}%"></span></span>
          ${r.passRate.toFixed(1)}%
        </td>
      </tr>
      ${ipMeta ? `<tr class="ip-meta-row"><td colspan="3">${ipMeta}</td></tr>` : ''}`
      }
      return `
      <tr data-name="${escapeHtml(r.name)}"${options.onRowClick ? ` title="${escapeHtml(t('filter.clickToFilter'))}"` : ''}>
        <td><span class="mono">${escapeHtml(r.name)}</span></td>
        <td>${r.count}</td>
        <td>
          <span class="rate-bar"><span style="width:${Math.min(100, r.passRate)}%"></span></span>
          ${r.passRate.toFixed(1)}%
        </td>
      </tr>`
    })
    .join('')

  if (options.onRowClick) {
    for (const tr of tbody.querySelectorAll<HTMLTableRowElement>('tr[data-name]')) {
      tr.addEventListener('click', (ev) => {
        const target = ev.target as HTMLElement
        if (target.closest('[data-ip-detail]')) return
        options.onRowClick?.(tr.dataset.name ?? '')
      })
    }
  }
  bindIpDetailButtons(tbody)
}

function renderFilterChips(): void {
  const chips: Array<{ key: keyof DrillFilters; label: string; value: string }> = []
  if (state.drill.org) chips.push({ key: 'org', label: t('table.org'), value: state.drill.org })
  if (state.drill.sourceIp)
    chips.push({ key: 'sourceIp', label: t('detail.ip'), value: state.drill.sourceIp })
  if (state.drill.headerFrom)
    chips.push({ key: 'headerFrom', label: t('detail.from'), value: state.drill.headerFrom })

  filterChipsEl.classList.toggle('hidden', chips.length === 0)
  filterChipsEl.innerHTML = chips
    .map(
      (c) => `
      <span class="chip">
        <span class="chip-label">${c.label}:</span>
        <span class="mono">${escapeHtml(c.value)}</span>
        <button type="button" class="chip-remove" data-chip="${c.key}" aria-label="${escapeHtml(t('filter.removeChip'))}">✕</button>
      </span>`
    )
    .join('')

  for (const btn of filterChipsEl.querySelectorAll<HTMLButtonElement>('.chip-remove')) {
    btn.addEventListener('click', () => {
      const key = btn.dataset.chip as keyof DrillFilters
      delete state.drill[key]
      applyView()
    })
  }
}

export function setDrillFilter(key: keyof DrillFilters, value: string): void {
  if (!value) return
  if (state.drill[key] === value) delete state.drill[key]
  else state.drill[key] = value
  applyView()
}

export function renderDomainAmpel(rows: DomainHealth[]): void {
  if (!rows.length) {
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.empty'))}</p>`
    return
  }
  domainAmpelEl.innerHTML = rows
    .map((h) => {
      const statusLabel = t(`health.status.${h.status}` as MessageKey)
      const policy =
        h.dmarcPolicy != null ? escapeHtml(t('health.policy', { policy: h.dmarcPolicy })) : '—'
      const reasons = h.reasons.map((key) => t(key as MessageKey)).join(' · ')
      return `
      <button type="button" class="ampel-card ${h.status}" data-domain="${escapeHtml(h.domain)}" title="${escapeHtml(statusLabel)}">
        <div class="ampel-domain">${escapeHtml(h.domain)}</div>
        <div class="ampel-meta">
          <span>${escapeHtml(statusLabel)}</span>
          <span>${escapeHtml(t('health.passRate', { rate: h.passRate.toFixed(1) }))}</span>
          <span>${escapeHtml(t('health.msgs', { count: String(h.total) }))}</span>
          <span>${policy}</span>
        </div>
        ${reasons ? `<div class="ampel-reasons">${escapeHtml(reasons)}</div>` : ''}
      </button>`
    })
    .join('')

  for (const btn of domainAmpelEl.querySelectorAll<HTMLButtonElement>('[data-domain]')) {
    btn.addEventListener('click', () => {
      const domain = btn.dataset.domain ?? ''
      if (!domain) return
      selectDomainFilter(domain)
      applyView()
    })
  }
}

/** Select a domain option case-insensitively (Ampel domains are lowercased). */
function selectDomainFilter(domain: string): void {
  const wanted = domain.trim().toLowerCase()
  const match = [...filterDomainEl.options].find((o) => o.value.toLowerCase() === wanted)
  filterDomainEl.value = match?.value ?? domain
}

function domainHealthFallback(reports: ReportRow[]): DomainHealth[] {
  return buildDomainStats(reports).map((stats) => mergeDomainHealth(stats, null))
}

/** Immediate Ampel numbers from filtered reports; keep prior DNS/status until batch returns. */
function domainHealthQuickStats(reports: ReportRow[]): DomainHealth[] {
  const prevByDomain = new Map(state.domainHealthCache.map((h) => [h.domain, h]))
  return buildDomainStats(reports).map((stats) => {
    const prev = prevByDomain.get(stats.domain)
    return prev ? { ...prev, ...stats } : mergeDomainHealth(stats, null)
  })
}

async function refreshDomainHealth(result: AnalyzeResult | null): Promise<void> {
  const token = ++state.domainHealthToken
  if (!domainAmpelEl) return
  if (!result || result.reports.length === 0) {
    state.domainHealthCache = []
    renderDomainAmpel([])
    return
  }

  // Update volume/pass-rate immediately from the filtered view (no loading flash).
  if (state.domainHealthCache.length) {
    const quick = domainHealthQuickStats(result.reports)
    state.domainHealthCache = quick
    renderDomainAmpel(quick)
  } else {
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.loading'))}</p>`
  }

  try {
    let health: DomainHealth[]
    if (typeof window.api.healthBatch === 'function') {
      health = await window.api.healthBatch(result.reports)
    } else {
      // Preload not yet reloaded — still show Ampel from local stats.
      health = domainHealthFallback(result.reports)
    }
    if (token !== state.domainHealthToken) return
    state.domainHealthCache = health
    renderDomainAmpel(health)
  } catch {
    if (token !== state.domainHealthToken) return
    state.domainHealthCache = domainHealthFallback(result.reports)
    renderDomainAmpel(state.domainHealthCache)
  }
}

function renderIpDetailBody(ip: string, rdapSummary?: string | null, rdapError?: string): void {
  const info = state.ipLabelCache.get(ip)
  const provider = info?.provider || info?.asOrg || null
  const geo =
    [info?.countryCode, info?.country, info?.city].filter(Boolean).join(' · ') || t('ipDetail.none')
  const asn =
    info?.asn != null ? `AS${info.asn}${info.asOrg ? ` (${info.asOrg})` : ''}` : t('ipDetail.none')
  const dnsbl = info?.dnsblHits?.length ? info.dnsblHits.join(', ') : t('ipDetail.none')
  const rdapText = rdapError || rdapSummary || t('ipDetail.none')
  ipDetailBody.innerHTML = `
    <dl>
      <dt>IP</dt><dd class="mono">${escapeHtml(ip)}</dd>
      <dt>${escapeHtml(t('ipDetail.ptr'))}</dt><dd>${escapeHtml(info?.ptr ?? t('ipDetail.none'))}</dd>
      <dt>${escapeHtml(t('ipDetail.provider'))}</dt><dd>${escapeHtml(provider ?? t('ipDetail.none'))}</dd>
      <dt>${escapeHtml(t('ipDetail.cloud'))}</dt><dd>${escapeHtml(info?.cloudProvider ?? t('ipDetail.none'))}</dd>
      <dt>${escapeHtml(t('ipDetail.geo'))}</dt><dd>${escapeHtml(geo)}</dd>
      <dt>${escapeHtml(t('ipDetail.asn'))}</dt><dd>${escapeHtml(asn)}</dd>
      <dt>${escapeHtml(t('ipDetail.dnsbl'))}</dt><dd>${escapeHtml(dnsbl)}</dd>
      <dt>${escapeHtml(t('ipDetail.rdap'))}</dt><dd id="ip-detail-rdap">${escapeHtml(rdapText)}</dd>
    </dl>`
}

export function openIpDetail(ip: string): void {
  if (!ip) return
  state.selectedDetailIp = ip
  renderIpDetailBody(ip)
  ipDetailDialog.showModal()
}

function renderDashboard(result: AnalyzeResult | null): void {
  if (!result) {
    setAlignmentChart(chartDmarc, { pass: 0, fail: 0, other: 0 })
    setAlignmentChart(chartSpf, { pass: 0, fail: 0, other: 0 })
    setAlignmentChart(chartDkim, { pass: 0, fail: 0, other: 0 })
    setDispositionChart([])
    clearVolumeChart()
    renderBucketTable(tableOrgs, [])
    renderBucketTable(tableIps, [])
    renderBucketTable(tableFrom, [])
    renderIpMap([])
    void refreshDomainHealth(null)
    return
  }

  const d = result.dashboard
  setAlignmentChart(chartDmarc, d.dmarc)
  setAlignmentChart(chartSpf, d.spf)
  setAlignmentChart(chartDkim, d.dkim)
  setDispositionChart(d.dispositions)

  setVolumeChart(
    d.volumeByDay.map((p) => p.date),
    d.volumeByDay.map((p) => p.passing),
    d.volumeByDay.map((p) => p.failing),
    d.volumeByDay.map((p) => p.passRate)
  )

  renderBucketTable(tableOrgs, d.byOrg, {
    onRowClick: (name) => setDrillFilter('org', name)
  })
  renderBucketTable(tableIps, d.bySourceIp, {
    withIpMeta: true,
    onRowClick: (name) => setDrillFilter('sourceIp', name)
  })
  renderBucketTable(tableFrom, d.byHeaderFrom, {
    onRowClick: (name) => setDrillFilter('headerFrom', name)
  })
  renderIpMap(d.bySourceIp)

  // Prefer enriching noise-candidate IPs so the Google filter can engage even when
  // those sources fall outside the displayed top-N IP table.
  const enrichIps: string[] = []
  const seen = new Set<string>()
  const pushIp = (ip: string): void => {
    if (!ip || seen.has(ip)) return
    seen.add(ip)
    enrichIps.push(ip)
  }
  if (filterHideGoogleNoiseEl.checked && state.fullResult) {
    for (const report of state.fullResult.reports) {
      for (const rec of report.records) {
        if (isGoogleNoiseAuthPattern(rec)) pushIp(rec.sourceIp)
      }
    }
  }
  for (const row of d.bySourceIp) pushIp(row.name)
  void enrichIpLabels(enrichIps)
  void refreshDomainHealth(result)
}

function collectGoogleIps(): Set<string> {
  const set = new Set<string>()
  for (const [ip, info] of state.ipLabelCache) {
    if (isGoogleIpInfo(info)) set.add(ip)
  }
  return set
}

async function enrichIpLabels(ips: string[]): Promise<void> {
  // When the Google-noise filter is on, resolve those candidates first (up to 40).
  const missing = ips.filter((ip) => !state.ipLabelCache.has(ip)).slice(0, 40)
  if (!missing.length) return
  try {
    const infos = await window.api.resolveIps(missing)
    let foundGoogle = false
    for (const info of infos) {
      state.ipLabelCache.set(info.ip, info)
      if (isGoogleIpInfo(info)) foundGoogle = true
    }
    // Re-filter once Google IPs are known so KPIs/charts/Ampel all update together.
    if (foundGoogle && filterHideGoogleNoiseEl.checked) {
      applyView()
      return
    }
    if (state.viewResult) {
      renderBucketTable(tableIps, state.viewResult.dashboard.bySourceIp, {
        withIpMeta: true,
        onRowClick: (name) => setDrillFilter('sourceIp', name)
      })
      renderIpMap(state.viewResult.dashboard.bySourceIp)
    }
    // Refresh open record details so geo/ASN/DNSBL appear once enrichment lands.
    if (state.selectedReportId && state.viewResult) {
      const selected =
        state.viewResult.reports.find((r) => r.reportId === state.selectedReportId) ?? null
      if (selected) renderDetail(selected)
    }
  } catch {
    // Enrichment ist optional.
  }
}

export function renderDetail(report: ReportRow | null): void {
  if (!report) {
    detailEl.innerHTML = `<p class="muted">${escapeHtml(t('detail.pick'))}</p>`
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
      const ipMeta = formatIpMetaHtml(r.sourceIp)
      return `
      <tr${ipMeta ? ' class="has-ip-meta"' : ''}>
        <td class="ip-col">${formatIpCellHtml(r.sourceIp, null, null, { includeMeta: false })}</td>
        <td>${r.count}</td>
        <td>${escapeHtml(r.disposition ?? '—')}</td>
        <td class="${r.dkimResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.dkimResult ?? '—')}</td>
        <td class="${r.spfResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.spfResult ?? '—')}</td>
        <td class="${r.passesDmarc ? 'pass' : 'fail'}">${r.passesDmarc ? 'pass' : 'fail'}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
        <td class="reasons">${reasons}</td>
      </tr>
      ${
        ipMeta
          ? `<tr class="ip-meta-row"><td colspan="8">${ipMeta}</td></tr>`
          : ''
      }`
    })
    .join('')

  detailEl.innerHTML = `
    <h3>${escapeHtml(report.orgName)} → ${escapeHtml(report.domain)}</h3>
    <div class="meta">
      ID: <span class="mono">${escapeHtml(report.reportId)}</span><br />
      ${escapeHtml(t('detail.period'))}: ${escapeHtml(formatRange(report.dateBegin, report.dateEnd))}<br />
      ${escapeHtml(t('detail.policy'))}: ${escapeHtml(report.policyP ?? '—')} ·
      ${report.passing}/${report.total} pass (${report.passRate.toFixed(1)}%)
    </div>
    <table>
      <thead>
        <tr>
          <th class="ip-col">${escapeHtml(t('table.ipSender'))}</th>
          <th>${escapeHtml(t('detail.count'))}</th>
          <th>${escapeHtml(t('detail.disp'))}</th>
          <th>${escapeHtml(t('detail.dkim'))}</th>
          <th>${escapeHtml(t('detail.spf'))}</th>
          <th>${escapeHtml(t('detail.dmarc'))}</th>
          <th>${escapeHtml(t('detail.from'))}</th>
          <th>${escapeHtml(t('detail.reasons'))}</th>
        </tr>
      </thead>
      <tbody>${rows || `<tr><td colspan="8">${escapeHtml(t('detail.noRecords'))}</td></tr>`}</tbody>
    </table>
  `
  bindIpDetailButtons(detailEl)
  void enrichIpLabels(report.records.map((r) => r.sourceIp).filter(Boolean))
}

function renderForensic(result: AnalyzeResult | null): void {
  const rows = result?.forensicReports ?? []
  if (rows.length === 0) {
    forensicBody.innerHTML = `<tr class="empty"><td colspan="7">${escapeHtml(t('table.forensicEmpty'))}</td></tr>`
    return
  }
  forensicBody.innerHTML = rows
    .map(
      (r: ForensicReportRow) => `
      <tr>
        <td>${escapeHtml(r.arrivalDate ? r.arrivalDate.slice(0, 19).replace('T', ' ') : '—')}</td>
        <td>${escapeHtml(r.reportedDomain ?? '—')}</td>
        <td class="mono">${escapeHtml(r.sourceIp ?? '—')}</td>
        <td>${escapeHtml(r.authFailure ?? '—')}</td>
        <td>${escapeHtml(r.envelopeFrom ?? '—')}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
        <td>${escapeHtml(r.feedbackType ?? '—')}</td>
      </tr>`
    )
    .join('')
}

async function downloadReportZip(report: ReportRow): Promise<void> {
  if (state.busy) return
  setBusy(true)
  try {
    const res = await window.api.exportReportZip(report)
    setStatus(res.message, res.ok ? 'ok' : '')
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    setBusy(false)
  }
}

export function renderReports(result: AnalyzeResult | null): void {
  reportsBody.innerHTML = ''
  if (!result || result.reports.length === 0) {
    reportsBody.innerHTML = `<tr class="empty"><td colspan="9">${escapeHtml(t('table.noReports'))}</td></tr>`
    renderDetail(null)
    return
  }

  for (const report of result.reports) {
    const tr = document.createElement('tr')
    tr.dataset.reportId = report.reportId
    if (report.reportId === state.selectedReportId) tr.classList.add('selected')
    tr.innerHTML = `
      <td>${escapeHtml(report.orgName)}</td>
      <td>${escapeHtml(report.domain)}</td>
      <td>${escapeHtml(formatRange(report.dateBegin, report.dateEnd))}</td>
      <td>${report.total}</td>
      <td class="pass">${report.passing}</td>
      <td class="fail">${report.failing}</td>
      <td>${report.passRate.toFixed(1)}%</td>
      <td>${escapeHtml(report.policyP ?? '—')}</td>
      <td class="col-actions">
        <button
          type="button"
          class="report-download-btn"
          data-report-download="${escapeHtml(report.reportId)}"
          title="${escapeHtml(t('table.downloadReport'))}"
          aria-label="${escapeHtml(t('table.downloadReport'))}"
        >
          <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path fill="currentColor" d="M16 11h5l-9 10-9-10h5v-11h8v11zm1 11h-10v2h10v-2z" />
          </svg>
        </button>
      </td>
    `
    tr.addEventListener('click', (ev) => {
      const target = ev.target as HTMLElement
      if (target.closest('[data-report-download]')) return
      state.selectedReportId = report.reportId
      for (const row of reportsBody.querySelectorAll('tr')) row.classList.remove('selected')
      tr.classList.add('selected')
      renderDetail(report)
    })
    const downloadBtn = tr.querySelector<HTMLButtonElement>('[data-report-download]')
    downloadBtn?.addEventListener('click', (ev) => {
      ev.stopPropagation()
      void downloadReportZip(report)
    })
    reportsBody.appendChild(tr)
  }

  const selected =
    result.reports.find((r) => r.reportId === state.selectedReportId) ?? result.reports[0] ?? null
  state.selectedReportId = selected?.reportId ?? null
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
    `<option value="">${escapeHtml(t('filter.allDomains'))}</option>` +
    domains.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('')
  if (domains.includes(current)) filterDomainEl.value = current
  if (domains.length === 1 && !dnsDomainEl.value) {
    dnsDomainEl.value = domains[0]
  }
}

export function applyView(): void {
  renderFilterChips()
  if (!state.fullResult) {
    state.viewResult = null
    updateSummary(null)
    renderDashboard(null)
    renderReports(null)
    renderForensic(null)
    btnExport.disabled = true
    return
  }

  const hideGoogleNoise = filterHideGoogleNoiseEl.checked
  state.viewResult = applyDashboardFilter(state.fullResult, {
    range: filterRangeEl.value as DateRangePreset,
    from: filterFromEl.value || undefined,
    to: filterToEl.value || undefined,
    domain: filterDomainEl.value,
    org: state.drill.org,
    sourceIp: state.drill.sourceIp,
    headerFrom: state.drill.headerFrom,
    hideGoogleNoise,
    googleIps: hideGoogleNoise ? collectGoogleIps() : undefined
  })
  updateSummary(state.viewResult)
  renderDashboard(state.viewResult)
  renderReports(state.viewResult)
  renderForensic(state.viewResult)
  btnExport.disabled =
    state.viewResult.reports.length === 0 && (state.viewResult.forensicReports?.length ?? 0) === 0
}

export function showResult(result: AnalyzeResult, statusMessage?: string): void {
  state.fullResult = result
  fillDomainFilter(result)
  applyView()
  if (statusMessage) {
    setStatus(statusMessage, 'ok')
  } else {
    const skippedNote = result.skipped ? t('status.skippedPart', { count: result.skipped }) : ''
    const newNote =
      result.newReports != null ? t('status.newPart', { count: result.newReports }) : ''
    const cacheNote = result.fromCache ? t('status.cachePart') : ''
    const sourceNote = result.newSourceIps?.length
      ? t('status.sourcePart', { count: result.newSourceIps.length })
      : ''
    setStatus(
      t('status.result', {
        reports: result.aggregate.reportCount,
        newNote,
        cacheNote,
        messages: result.aggregate.total,
        skippedNote,
        sourceNote
      }),
      'ok'
    )
  }
}

export function initView(): void {
  setIpMapFilterHandler((ip) => setDrillFilter('sourceIp', ip))

  btnCloseIpDetail.addEventListener('click', () => ipDetailDialog.close())
  btnIpFilter.addEventListener('click', () => {
    if (!state.selectedDetailIp) return
    ipDetailDialog.close()
    setDrillFilter('sourceIp', state.selectedDetailIp)
  })
  btnIpRdap.addEventListener('click', async () => {
    if (!state.selectedDetailIp) return
    const rdapEl = document.getElementById('ip-detail-rdap')
    if (rdapEl) rdapEl.textContent = t('ipDetail.loadingRdap')
    try {
      const info = await window.api.lookupRdap(state.selectedDetailIp)
      renderIpDetailBody(state.selectedDetailIp, info.rawSummary, info.error)
    } catch (err) {
      renderIpDetailBody(
        state.selectedDetailIp,
        null,
        err instanceof Error ? err.message : String(err)
      )
    }
  })

  filterRangeEl.addEventListener('change', () => {
    filterCustomWrap.classList.toggle('hidden', filterRangeEl.value !== 'custom')
    applyView()
  })
  filterFromEl.addEventListener('change', () => applyView())
  filterToEl.addEventListener('change', () => applyView())
  filterDomainEl.addEventListener('change', () => applyView())
  filterHideGoogleNoiseEl.addEventListener('change', () => {
    applyView()
    void persistHideGoogleNoise()
  })
}

async function persistHideGoogleNoise(): Promise<void> {
  if (!state.settings) return
  try {
    const next = await window.api.saveGlobalSettings({
      ...state.settings.global,
      hideGoogleNoise: filterHideGoogleNoiseEl.checked
    })
    state.settings = next
  } catch {
    // Persistenz ist optional für den Dashboard-Filter.
  }
}
