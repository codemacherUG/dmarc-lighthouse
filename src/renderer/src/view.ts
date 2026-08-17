import {
  applyDashboardFilter,
  buildDomainStats,
  categorizeFailure,
  DOMAIN_HEALTH_WINDOW_DAYS,
  groupProblemSources,
  isMailboxIpInfo,
  isMailboxNoiseAuthPattern,
  mergeDomainHealth,
  normalizeDispositionFilter,
  parseSourceIpFilter,
  reportsForDomainHealth
} from '../../shared/analyze'
import { isAuthorizedSender, parseAuthorizedSenderPrefixes } from '../../shared/ipcidr'
import { t, type MessageKey } from '../../shared/i18n'
import {
  DEFAULT_DATE_RANGE,
  type AnalyzeResult,
  type DateRangePreset,
  type DomainHealth,
  type FailCategory,
  type ForensicReportRow,
  type NamedBucket,
  type ProblemSourceRow,
  type ReportRow
} from '../../shared/types'
import {
  chartDkim,
  chartDmarc,
  chartSpf,
  clearVolumeChart,
  setAlignmentChart,
  setDispositionChart,
  setVolumeChart,
  setVolumeDayClickHandler
} from './charts'
import { setBusy, setStatus } from './chrome'
import {
  btnCloseIpDetail,
  btnExport,
  btnFilterReset,
  btnIpFilter,
  btnIpRdap,
  detailEl,
  dnsDomainEl,
  domainAmpelEl,
  tableProblemSources,
  filterChipsEl,
  filterDomainEl,
  filterFromEl,
  filterHideMailboxNoiseEl,
  filterPanelEl,
  filterRangeEl,
  filterToEl,
  filterCustomWrap,
  filterDispositionEl,
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
import { clearDrill, state, type DrillFilters } from './state'
import {
  compareIp,
  compareNumber,
  compareText,
  createWindowedTable,
  enableRowKeyboardNav,
  initSortableHeader,
  sortRows,
  type SortColumn,
  type SortState,
  type WindowedTable
} from './table'

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

/** Drop cached SPF marks (e.g. on account switch) so badges never use another account's expand. */
export function clearSpfMarks(): void {
  state.spfExpandToken++
  state.spfPrefixes = []
}

/** Re-render views that embed SPF badges after prefixes change. */
function renderAfterSpfMarksUpdate(): void {
  if (state.viewResult) {
    renderIpTable(state.viewResult.dashboard.bySourceIp)
    renderProblemSources(state.viewResult.dashboard.problemSources ?? [])
  }
  if (state.selectedReportId && state.viewResult) {
    const selected =
      state.viewResult.reports.find((r) => r.reportId === state.selectedReportId) ?? null
    if (selected) renderDetail(selected)
  }
}

/** Expand SPF for report domains and cache prefixes for IP badges. */
async function refreshSpfMarks(): Promise<void> {
  if (typeof window.api.expandSpf !== 'function') return
  const domains = state.fullResult?.aggregate.domains ?? []
  const filterDomain = filterDomainEl.value.trim()
  const targets = (filterDomain ? [filterDomain] : domains)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 8)
  const token = ++state.spfExpandToken
  // Invalidate immediately — never keep the previous account/domain's CIDRs while loading.
  state.spfPrefixes = []
  if (!targets.length) {
    renderAfterSpfMarksUpdate()
    return
  }
  const cidrs = new Set<string>()
  await Promise.all(
    targets.map(async (domain) => {
      try {
        const result = await window.api.expandSpf(domain)
        for (const c of result.cidrs) cidrs.add(c)
      } catch {
        // ignore per-domain SPF expand failures
      }
    })
  )
  if (token !== state.spfExpandToken) return
  state.spfPrefixes = parseAuthorizedSenderPrefixes([...cidrs])
  renderAfterSpfMarksUpdate()
}

/** Sort keys shared by the three aggregate tables (org, IP, from-domain). */
type BucketSortKey = 'name' | 'count' | 'rate'

const BUCKET_COLUMNS: Array<SortColumn<BucketSortKey>> = [
  { key: 'name' },
  { key: 'count', firstDir: 'desc' },
  { key: 'rate', firstDir: 'desc' }
]

const sortOrgs: SortState<BucketSortKey> = { key: 'count', dir: 'desc' }
const sortIps: SortState<BucketSortKey> = { key: 'count', dir: 'desc' }
const sortFrom: SortState<BucketSortKey> = { key: 'count', dir: 'desc' }

function compareBucket(
  a: NamedBucket,
  b: NamedBucket,
  key: BucketSortKey,
  ipAware: boolean
): number {
  if (key === 'count') return compareNumber(a.count, b.count)
  if (key === 'rate') return compareNumber(a.passRate, b.passRate)
  return ipAware ? compareIp(a.name, b.name) : compareText(a.name, b.name)
}

function renderBucketTable(
  tbody: HTMLTableSectionElement,
  rows: NamedBucket[],
  options: {
    withIpMeta?: boolean
    sort?: SortState<BucketSortKey>
    onRowClick?: (name: string) => void
  } = {}
): void {
  const cols = 3
  if (!rows.length) {
    tbody.innerHTML = `<tr class="empty"><td colspan="${cols}">${escapeHtml(t('table.noData'))}</td></tr>`
    return
  }
  const sorted = options.sort
    ? sortRows(rows, options.sort, (a, b, key) =>
        compareBucket(a, b, key, Boolean(options.withIpMeta))
      )
    : rows
  // Only the primary row is focusable; the meta row stays clickable but out of the tab order.
  const clickAttrs = options.onRowClick
    ? ` tabindex="0" title="${escapeHtml(t('filter.clickToFilter'))}"`
    : ''
  const metaClickAttrs = options.onRowClick
    ? ` title="${escapeHtml(t('filter.clickToFilter'))}"`
    : ''
  tbody.innerHTML = sorted
    .map((r) => {
      if (options.withIpMeta) {
        const ipMeta = formatIpMetaHtml(r.name, r.provider, r.label)
        return `
      <tr data-name="${escapeHtml(r.name)}"${ipMeta ? ' class="has-ip-meta"' : ''}${clickAttrs}>
        <td class="ip-col">${formatIpCellHtml(r.name, r.provider, r.label, { includeMeta: false })}</td>
        <td>${r.count}</td>
        <td>
          <span class="rate-bar"><span style="width:${Math.min(100, r.passRate)}%"></span></span>
          ${r.passRate.toFixed(1)}%
        </td>
      </tr>
      ${ipMeta ? `<tr class="ip-meta-row" data-name="${escapeHtml(r.name)}"${metaClickAttrs}><td colspan="${cols}">${ipMeta}</td></tr>` : ''}`
      }
      return `
      <tr data-name="${escapeHtml(r.name)}"${clickAttrs}>
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
        if (target.closest('[data-ip-detail]')) {
          return
        }
        options.onRowClick?.(tr.dataset.name ?? '')
      })
    }
  }
  bindIpDetailButtons(tbody)
}

/** Render the source-IP table with its current sort and drill-down handler. */
function renderIpTable(rows: NamedBucket[]): void {
  renderBucketTable(tableIps, rows, {
    withIpMeta: true,
    sort: sortIps,
    onRowClick: (name) => setDrillFilter('sourceIp', name)
  })
}

function problemSourceFilterValue(row: ProblemSourceRow): string {
  return [row.sourceIp, ...(row.extraIps ?? [])].sort().join(',')
}

function formatSourceIpChip(value: string): string {
  const ips = parseSourceIpFilter(value)
  if (!ips || ips.length <= 1) return value
  const info = state.ipLabelCache.get(ips[0])
  const label =
    info?.cloudProvider || info?.provider || (info?.asn != null ? `AS${info.asn}` : ips[0])
  return t('problems.ipGroupChip', { label, count: ips.length })
}

type ProblemSortKey = 'ip' | 'from' | 'category' | 'count' | 'spf' | 'dkim'

const PROBLEM_COLUMNS: Array<SortColumn<ProblemSortKey>> = [
  { key: 'ip' },
  { key: 'from' },
  { key: 'category' },
  { key: 'count', firstDir: 'desc' },
  { key: 'spf', firstDir: 'desc' },
  { key: 'dkim', firstDir: 'desc' }
]

const sortProblems: SortState<ProblemSortKey> = { key: 'count', dir: 'desc' }

function compareProblemSource(
  a: ProblemSourceRow,
  b: ProblemSourceRow,
  key: ProblemSortKey
): number {
  switch (key) {
    case 'ip':
      return compareIp(a.sourceIp, b.sourceIp)
    case 'from':
      return compareText(a.headerFrom, b.headerFrom)
    case 'spf':
      return compareNumber(a.spfFail, b.spfFail)
    case 'dkim':
      return compareNumber(a.dkimFail, b.dkimFail)
    case 'category':
      return compareText(problemCategoryLabel(a), problemCategoryLabel(b))
    default:
      return compareNumber(a.count, b.count)
  }
}

type DisplayCategory = FailCategory | 'ownSender'

/**
 * An IP that our own SPF authorizes is never a stranger: whatever the record
 * looks like, the fix is alignment on a sender we already permitted.
 */
function refineCategory(base: FailCategory, ips: string[]): DisplayCategory {
  if (base === 'forwarder') return base
  if (ips.some((ip) => isAuthorizedSender(ip, state.spfPrefixes))) return 'ownSender'
  return base
}

function problemCategory(row: ProblemSourceRow): DisplayCategory {
  return refineCategory(row.category ?? 'unauthenticated', [row.sourceIp, ...(row.extraIps ?? [])])
}

function problemCategoryLabel(row: ProblemSourceRow): string {
  return t(`problems.cat.${problemCategory(row)}`)
}

const CATEGORY_BADGE_CLASS: Record<DisplayCategory, string> = {
  forwarder: 'badge',
  thirdParty: 'badge cloud',
  broken: 'badge warn',
  ownSender: 'badge warn',
  unauthenticated: 'badge bad'
}

function categoryBadgeHtml(category: DisplayCategory): string {
  const hint = t(`problems.catHint.${category}`)
  return `<span class="${CATEGORY_BADGE_CLASS[category]}" title="${escapeHtml(hint)}">${escapeHtml(
    t(`problems.cat.${category}`)
  )}</span>`
}

function problemCategoryHtml(row: ProblemSourceRow): string {
  return categoryBadgeHtml(problemCategory(row))
}

function renderProblemSources(rows: ProblemSourceRow[]): void {
  if (!tableProblemSources) return
  const grouped = groupProblemSources(rows, (ip) => state.ipLabelCache.get(ip)).slice(0, 40)
  if (!grouped.length) {
    tableProblemSources.innerHTML = `<tr class="empty"><td colspan="6">${escapeHtml(t('problems.empty'))}</td></tr>`
    return
  }
  tableProblemSources.innerHTML = sortRows(grouped, sortProblems, compareProblemSource)
    .map((r) => {
      const groupCount = 1 + (r.extraIps?.length ?? 0)
      const filterValue = problemSourceFilterValue(r)
      const ipMeta = formatIpMetaHtml(r.sourceIp, null, null, { groupedIpCount: groupCount })
      const rowClass = ipMeta ? 'has-ip-meta' : ''
      return `
      <tr data-name="${escapeHtml(filterValue)}" class="${rowClass}" tabindex="0" title="${escapeHtml(t('filter.clickToFilter'))}">
        <td class="ip-col">${formatIpCellHtml(r.sourceIp, null, null, { includeMeta: false })}</td>
        <td class="mono-from" title="${escapeHtml(r.headerFrom ?? '')}">${escapeHtml(r.headerFrom ?? '—')}</td>
        <td class="cat-col">${problemCategoryHtml(r)}</td>
        <td>${r.count}</td>
        <td>${r.spfFail}</td>
        <td>${r.dkimFail}</td>
      </tr>
      ${ipMeta ? `<tr class="ip-meta-row" data-name="${escapeHtml(filterValue)}" title="${escapeHtml(t('filter.clickToFilter'))}"><td colspan="6">${ipMeta}</td></tr>` : ''}`
    })
    .join('')

  for (const tr of tableProblemSources.querySelectorAll<HTMLTableRowElement>('tr[data-name]')) {
    tr.addEventListener('click', (ev) => {
      const target = ev.target as HTMLElement
      if (target.closest('[data-ip-detail]')) {
        return
      }
      setDrillFilter('sourceIp', tr.dataset.name ?? '')
    })
  }
  bindIpDetailButtons(tableProblemSources)
}

function renderFilterChips(): void {
  const chips: Array<{ key: keyof DrillFilters; label: string; value: string }> = []
  if (state.drill.org) chips.push({ key: 'org', label: t('table.org'), value: state.drill.org })
  if (state.drill.sourceIp)
    chips.push({
      key: 'sourceIp',
      label: t('detail.ip'),
      value: formatSourceIpChip(state.drill.sourceIp)
    })
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

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/

let rangeBeforeDayFilter: { range: string; from: string; to: string } | null = null

function syncCustomRangeVisibility(): void {
  filterCustomWrap.classList.toggle('hidden', filterRangeEl.value !== 'custom')
}

function hasActiveFilters(): boolean {
  return (
    filterRangeEl.value !== DEFAULT_DATE_RANGE ||
    Boolean(filterFromEl.value) ||
    Boolean(filterToEl.value) ||
    Boolean(filterDomainEl.value) ||
    filterDispositionEl.value !== 'all' ||
    filterHideMailboxNoiseEl.checked ||
    Boolean(state.drill.org || state.drill.sourceIp || state.drill.headerFrom)
  )
}

function syncFilterResetButton(): void {
  btnFilterReset.disabled = !hasActiveFilters()
}

export function resetFilters(): void {
  const noiseWasOn = filterHideMailboxNoiseEl.checked
  filterRangeEl.value = DEFAULT_DATE_RANGE
  filterFromEl.value = ''
  filterToEl.value = ''
  filterDomainEl.value = ''
  filterDispositionEl.value = 'all'
  filterHideMailboxNoiseEl.checked = false
  rangeBeforeDayFilter = null
  clearDrill()
  syncCustomRangeVisibility()
  applyView()
  if (noiseWasOn) void persistHideMailboxNoise()
}

/** Filter dashboard to the volume-chart day, or restore the previous range on a second click. */
export function filterVolumeByDay(date: string): void {
  if (!DAY_RE.test(date)) return
  const already =
    filterRangeEl.value === 'custom' && filterFromEl.value === date && filterToEl.value === date
  if (already) {
    if (rangeBeforeDayFilter) {
      filterRangeEl.value = rangeBeforeDayFilter.range
      filterFromEl.value = rangeBeforeDayFilter.from
      filterToEl.value = rangeBeforeDayFilter.to
      rangeBeforeDayFilter = null
    } else {
      filterRangeEl.value = DEFAULT_DATE_RANGE
      filterFromEl.value = ''
      filterToEl.value = ''
    }
  } else {
    rangeBeforeDayFilter = {
      range: filterRangeEl.value,
      from: filterFromEl.value,
      to: filterToEl.value
    }
    filterRangeEl.value = 'custom'
    filterFromEl.value = date
    filterToEl.value = date
  }
  syncCustomRangeVisibility()
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
          <span>${escapeHtml(t('health.window', { days: String(DOMAIN_HEALTH_WINDOW_DAYS) }))}</span>
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
  return buildDomainStats(reportsForDomainHealth(reports)).map((stats) =>
    mergeDomainHealth(stats, null)
  )
}

/** Immediate Ampel numbers from the 14-day window; keep prior DNS/status until batch returns. */
function domainHealthQuickStats(reports: ReportRow[]): DomainHealth[] {
  const prevByDomain = new Map(state.domainHealthCache.map((h) => [h.domain, h]))
  return buildDomainStats(reportsForDomainHealth(reports)).map((stats) => {
    const prev = prevByDomain.get(stats.domain)
    return prev ? { ...prev, ...stats } : mergeDomainHealth(stats, null)
  })
}

/** Last AnalyzeResult used for Ampel — skip re-fetch when only dashboard filters change. */
let domainHealthSource: AnalyzeResult | null = null

/**
 * Ampel always uses the full loaded report set, windowed to the last
 * {@link DOMAIN_HEALTH_WINDOW_DAYS} days — not the dashboard date filter.
 */
async function refreshDomainHealth(full: AnalyzeResult | null): Promise<void> {
  if (!domainAmpelEl) return
  if (full && full === domainHealthSource) return
  domainHealthSource = full

  const token = ++state.domainHealthToken
  const source = full?.reports ?? []
  if (!source.length) {
    state.domainHealthCache = []
    renderDomainAmpel([])
    return
  }

  const windowed = reportsForDomainHealth(source)
  if (!windowed.length) {
    state.domainHealthCache = []
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(
      t('health.emptyWindow', { days: String(DOMAIN_HEALTH_WINDOW_DAYS) })
    )}</p>`
    return
  }

  // Update volume/pass-rate immediately (no loading flash when cache exists).
  if (state.domainHealthCache.length) {
    const quick = domainHealthQuickStats(source)
    state.domainHealthCache = quick
    renderDomainAmpel(quick)
  } else {
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.loading'))}</p>`
  }

  try {
    let health: DomainHealth[]
    if (typeof window.api.healthBatch === 'function') {
      health = await window.api.healthBatch(windowed)
    } else {
      // Preload not yet reloaded — still show Ampel from local stats.
      health = domainHealthFallback(windowed)
    }
    if (token !== state.domainHealthToken) return
    state.domainHealthCache = health
    renderDomainAmpel(health)
  } catch {
    if (token !== state.domainHealthToken) return
    state.domainHealthCache = domainHealthFallback(windowed)
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
    renderProblemSources([])
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
    sort: sortOrgs,
    onRowClick: (name) => setDrillFilter('org', name)
  })
  renderIpTable(d.bySourceIp)
  renderBucketTable(tableFrom, d.byHeaderFrom, {
    sort: sortFrom,
    onRowClick: (name) => setDrillFilter('headerFrom', name)
  })
  renderProblemSources(d.problemSources ?? [])
  renderIpMap(d.bySourceIp)
  void refreshSpfMarks()

  // Prefer enriching noise-candidate IPs so the mailbox filter can engage even when
  // those sources fall outside the displayed top-N IP table.
  const enrichIps: string[] = []
  const seen = new Set<string>()
  const pushIp = (ip: string): void => {
    if (!ip || seen.has(ip)) return
    seen.add(ip)
    enrichIps.push(ip)
  }
  if (filterHideMailboxNoiseEl.checked && state.fullResult) {
    for (const report of state.fullResult.reports) {
      for (const rec of report.records) {
        if (isMailboxNoiseAuthPattern(rec)) pushIp(rec.sourceIp)
      }
    }
  }
  for (const row of d.bySourceIp) pushIp(row.name)
  for (const row of d.problemSources ?? []) pushIp(row.sourceIp)
  void enrichIpLabels(enrichIps)
  // Ampel ignores the dashboard date filter — always last N days of fullResult.
  void refreshDomainHealth(state.fullResult)
}

function collectMailboxIps(): Set<string> {
  const set = new Set<string>()
  for (const [ip, info] of state.ipLabelCache) {
    if (isMailboxIpInfo(info)) set.add(ip)
  }
  return set
}

async function enrichIpLabels(ips: string[]): Promise<void> {
  // When the mailbox-noise filter is on, resolve those candidates first (up to 40).
  const missing = ips.filter((ip) => !state.ipLabelCache.has(ip)).slice(0, 40)
  if (!missing.length) return
  try {
    const infos = await window.api.resolveIps(missing)
    let foundMailbox = false
    for (const info of infos) {
      state.ipLabelCache.set(info.ip, info)
      if (isMailboxIpInfo(info)) foundMailbox = true
    }
    // Re-filter once mailbox IPs are known so KPIs/charts/Ampel all update together.
    if (foundMailbox && filterHideMailboxNoiseEl.checked) {
      applyView()
      return
    }
    if (state.viewResult) {
      renderIpTable(state.viewResult.dashboard.bySourceIp)
      renderProblemSources(state.viewResult.dashboard.problemSources ?? [])
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
          : ''
      const cause = r.passesDmarc
        ? ''
        : categoryBadgeHtml(
            refineCategory(categorizeFailure(r, report.domain), [r.sourceIp].filter(Boolean))
          )
      const reasonCell = [cause, reasons].filter(Boolean).join('<br />') || '—'
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
        <td class="reasons">${reasonCell}</td>
      </tr>
      ${ipMeta ? `<tr class="ip-meta-row"><td colspan="8">${ipMeta}</td></tr>` : ''}`
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

type ForensicSortKey =
  'arrival' | 'domain' | 'ip' | 'authFailure' | 'envelopeFrom' | 'headerFrom' | 'type'

const FORENSIC_COLUMNS: Array<SortColumn<ForensicSortKey>> = [
  { key: 'arrival', firstDir: 'desc' },
  { key: 'domain' },
  { key: 'ip' },
  { key: 'authFailure' },
  { key: 'envelopeFrom' },
  { key: 'headerFrom' },
  { key: 'type' }
]

const sortForensic: SortState<ForensicSortKey> = { key: 'arrival', dir: 'desc' }

function compareForensic(a: ForensicReportRow, b: ForensicReportRow, key: ForensicSortKey): number {
  switch (key) {
    case 'domain':
      return compareText(a.reportedDomain, b.reportedDomain)
    case 'ip':
      return compareIp(a.sourceIp ?? '', b.sourceIp ?? '')
    case 'authFailure':
      return compareText(a.authFailure, b.authFailure)
    case 'envelopeFrom':
      return compareText(a.envelopeFrom, b.envelopeFrom)
    case 'headerFrom':
      return compareText(a.headerFrom, b.headerFrom)
    case 'type':
      return compareText(a.feedbackType, b.feedbackType)
    default:
      return compareText(a.arrivalDate, b.arrivalDate)
  }
}

function forensicRowElement(r: ForensicReportRow): HTMLTableRowElement {
  const tr = document.createElement('tr')
  tr.innerHTML = `
    <td>${escapeHtml(r.arrivalDate ? r.arrivalDate.slice(0, 19).replace('T', ' ') : '—')}</td>
    <td>${escapeHtml(r.reportedDomain ?? '—')}</td>
    <td class="mono">${escapeHtml(r.sourceIp ?? '—')}</td>
    <td>${escapeHtml(r.authFailure ?? '—')}</td>
    <td>${escapeHtml(r.envelopeFrom ?? '—')}</td>
    <td>${escapeHtml(r.headerFrom ?? '—')}</td>
    <td>${escapeHtml(r.feedbackType ?? '—')}</td>`
  return tr
}

let forensicTable: WindowedTable<ForensicReportRow> | null = null

function renderForensic(result: AnalyzeResult | null): void {
  const rows = result?.forensicReports ?? []
  forensicTable?.setRows(rows.length ? sortRows(rows, sortForensic, compareForensic) : [])
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

type ReportSortKey =
  'org' | 'domain' | 'period' | 'total' | 'passing' | 'failing' | 'rate' | 'policy'

const REPORT_COLUMNS: Array<SortColumn<ReportSortKey>> = [
  { key: 'org' },
  { key: 'domain' },
  { key: 'period', firstDir: 'desc' },
  { key: 'total', firstDir: 'desc' },
  { key: 'passing', firstDir: 'desc' },
  { key: 'failing', firstDir: 'desc' },
  { key: 'rate', firstDir: 'desc' },
  { key: 'policy' },
  { key: null }
]

const sortReports: SortState<ReportSortKey> = { key: 'period', dir: 'desc' }

function compareReport(a: ReportRow, b: ReportRow, key: ReportSortKey): number {
  switch (key) {
    case 'org':
      return compareText(a.orgName, b.orgName)
    case 'domain':
      return compareText(a.domain, b.domain)
    case 'total':
      return compareNumber(a.total, b.total)
    case 'passing':
      return compareNumber(a.passing, b.passing)
    case 'failing':
      return compareNumber(a.failing, b.failing)
    case 'rate':
      return compareNumber(a.passRate, b.passRate)
    case 'policy':
      return compareText(a.policyP, b.policyP)
    default:
      return compareText(a.dateEnd || a.dateBegin, b.dateEnd || b.dateBegin)
  }
}

function reportRowElement(report: ReportRow): HTMLTableRowElement {
  const tr = document.createElement('tr')
  tr.dataset.reportId = report.reportId
  tr.tabIndex = 0
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
    for (const row of reportsBody.querySelectorAll('tr.selected')) row.classList.remove('selected')
    tr.classList.add('selected')
    renderDetail(report)
  })
  const downloadBtn = tr.querySelector<HTMLButtonElement>('[data-report-download]')
  downloadBtn?.addEventListener('click', (ev) => {
    ev.stopPropagation()
    void downloadReportZip(report)
  })
  return tr
}

let reportsTable: WindowedTable<ReportRow> | null = null

export function renderReports(result: AnalyzeResult | null): void {
  const rows = result ? sortRows(result.reports, sortReports, compareReport) : []
  if (rows.length === 0) {
    state.selectedReportId = null
    reportsTable?.setRows([])
    renderDetail(null)
    return
  }
  // Keep the selection when it survives the filter, otherwise take the first row.
  const selected = rows.find((r) => r.reportId === state.selectedReportId) ?? rows[0]!
  state.selectedReportId = selected.reportId
  reportsTable?.setRows(rows)
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
  syncFilterResetButton()
  if (!state.fullResult) {
    state.viewResult = null
    state.spfExpandToken++
    state.spfPrefixes = []
    updateSummary(null)
    renderDashboard(null)
    renderReports(null)
    renderForensic(null)
    btnExport.disabled = true
    return
  }

  const hideMailboxNoise = filterHideMailboxNoiseEl.checked
  state.viewResult = applyDashboardFilter(state.fullResult, {
    range: filterRangeEl.value as DateRangePreset,
    from: filterFromEl.value || undefined,
    to: filterToEl.value || undefined,
    domain: filterDomainEl.value,
    disposition: normalizeDispositionFilter(filterDispositionEl.value),
    org: state.drill.org,
    sourceIp: state.drill.sourceIp,
    headerFrom: state.drill.headerFrom,
    hideMailboxNoise,
    mailboxIps: hideMailboxNoise ? collectMailboxIps() : undefined
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

function initStickyFilter(): void {
  const panel = filterPanelEl
  const slot = panel?.closest('.filter-slot')
  const placeholder = slot?.querySelector<HTMLElement>('.filter-slot-ph')
  if (!panel || !slot || !placeholder) return

  let stuck = false
  let ticking = false

  const syncFixedBox = (): void => {
    const rect = slot.getBoundingClientRect()
    panel.style.left = `${rect.left}px`
    panel.style.width = `${rect.width}px`
  }

  const setStuck = (next: boolean): void => {
    if (next === stuck) return
    if (next) {
      placeholder.style.height = `${panel.offsetHeight}px`
      placeholder.hidden = false
      panel.classList.add('is-stuck')
      syncFixedBox()
    } else {
      panel.classList.remove('is-stuck')
      panel.style.left = ''
      panel.style.width = ''
      placeholder.hidden = true
      placeholder.style.height = ''
    }
    stuck = next
  }

  const update = (): void => {
    ticking = false
    const rect = slot.getBoundingClientRect()
    if (stuck) {
      if (rect.bottom > 8) setStuck(false)
      else syncFixedBox()
    } else if (rect.bottom <= 0) {
      setStuck(true)
    }
  }

  const onScrollOrResize = (): void => {
    if (ticking) return
    ticking = true
    requestAnimationFrame(update)
  }

  window.addEventListener('scroll', onScrollOrResize, { passive: true })
  window.addEventListener('resize', onScrollOrResize)
}

/** Wire up column sorting, keyboard row navigation and windowed row rendering. */
function initTables(): void {
  reportsTable = createWindowedTable<ReportRow>({
    body: reportsBody,
    columns: 9,
    renderRow: reportRowElement,
    renderEmpty: () =>
      `<tr class="empty"><td colspan="9">${escapeHtml(t('table.noReports'))}</td></tr>`
  })
  forensicTable = createWindowedTable<ForensicReportRow>({
    body: forensicBody,
    columns: 7,
    renderRow: forensicRowElement,
    renderEmpty: () =>
      `<tr class="empty"><td colspan="7">${escapeHtml(t('table.forensicEmpty'))}</td></tr>`
  })

  initSortableHeader({
    table: reportsBody.closest('table'),
    columns: REPORT_COLUMNS,
    state: sortReports,
    onSort: () => renderReports(state.viewResult)
  })
  initSortableHeader({
    table: forensicBody.closest('table'),
    columns: FORENSIC_COLUMNS,
    state: sortForensic,
    onSort: () => renderForensic(state.viewResult)
  })
  initSortableHeader({
    table: tableProblemSources?.closest('table'),
    columns: PROBLEM_COLUMNS,
    state: sortProblems,
    onSort: () => renderProblemSources(state.viewResult?.dashboard.problemSources ?? [])
  })
  initSortableHeader({
    table: tableOrgs.closest('table'),
    columns: BUCKET_COLUMNS,
    state: sortOrgs,
    onSort: () =>
      renderBucketTable(tableOrgs, state.viewResult?.dashboard.byOrg ?? [], {
        sort: sortOrgs,
        onRowClick: (name) => setDrillFilter('org', name)
      })
  })
  initSortableHeader({
    table: tableIps.closest('table'),
    columns: BUCKET_COLUMNS,
    state: sortIps,
    onSort: () => renderIpTable(state.viewResult?.dashboard.bySourceIp ?? [])
  })
  initSortableHeader({
    table: tableFrom.closest('table'),
    columns: BUCKET_COLUMNS,
    state: sortFrom,
    onSort: () =>
      renderBucketTable(tableFrom, state.viewResult?.dashboard.byHeaderFrom ?? [], {
        sort: sortFrom,
        onRowClick: (name) => setDrillFilter('headerFrom', name)
      })
  })

  for (const body of [reportsBody, tableOrgs, tableIps, tableFrom, tableProblemSources]) {
    enableRowKeyboardNav(body)
  }
}

export function initView(): void {
  initStickyFilter()
  initTables()
  setIpMapFilterHandler((ip) => setDrillFilter('sourceIp', ip))
  setVolumeDayClickHandler(filterVolumeByDay)

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
    rangeBeforeDayFilter = null
    syncCustomRangeVisibility()
    applyView()
  })
  filterFromEl.addEventListener('change', () => applyView())
  filterToEl.addEventListener('change', () => applyView())
  filterDomainEl.addEventListener('change', () => applyView())
  filterDispositionEl.addEventListener('change', () => applyView())
  filterHideMailboxNoiseEl.addEventListener('change', () => {
    applyView()
    void persistHideMailboxNoise()
  })
  btnFilterReset.addEventListener('click', () => resetFilters())
}

async function persistHideMailboxNoise(): Promise<void> {
  if (!state.settings) return
  try {
    const next = await window.api.saveGlobalSettings({
      ...state.settings.global,
      hideMailboxNoise: filterHideMailboxNoiseEl.checked
    })
    state.settings = next
  } catch {
    // Persistenz ist optional für den Dashboard-Filter.
  }
}
