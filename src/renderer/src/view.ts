import {
  applyDashboardFilter,
  analyzeFromReports,
  categorizeFailure,
  groupProblemSources,
  isMailboxIpInfo,
  isMailboxNoiseAuthPattern,
  isScannerNoiseIpInfo,
  normalizeDispositionFilter,
  parseSourceIpFilter
} from '../../shared/analyze'
import {
  isAuthorizedSender,
  parseAuthorizedSenderPrefixes,
  type CloudPrefix
} from '../../shared/ipcidr'
import {
  DEFAULT_MAILBOX_NOISE_PROVIDERS,
  parseMailboxNoiseProviders
} from '../../shared/mailbox-ip'
import {
  appendScannerNoiseEntries,
  DEFAULT_SCANNER_NOISE_HOSTS,
  matchesScannerNoise,
  parseScannerNoiseHosts,
  suggestScannerNoiseEntry
} from '../../shared/scanner-noise'
import { t, type MessageKey } from '../../shared/i18n'
import { simulateRolloutReports, type RolloutSimulationMode } from '../../shared/rollout'
import {
  DEFAULT_DATE_RANGE,
  type AnalyzeResult,
  type DateRangePreset,
  type FailCategory,
  type ForensicReportRow,
  type NamedBucket,
  type ProblemSourceRow,
  type ReportRow
} from '../../shared/types'
import {
  refreshDomainHealth,
  renderDomainAmpel,
  setAmpelDomainChangedCallback,
  syncDomainAmpelSelection
} from './ampel-view'
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
import { readDashboardUiState, writeDashboardUiState } from './dashboard-ui-state'
import { initDiagnosisModalEvents, openDiagnosis } from './diagnosis-modal'
import {
  btnCloseIpDetail,
  btnExport,
  btnFilterReset,
  btnIpFilter,
  btnIpNoise,
  btnIpRdap,
  btnResetIgnoredProblemSources,
  detailEl,
  ipContextMenu,
  ipContextNoiseBtn,
  ipContextSendingServiceBtn,
  dnsDialog,
  dnsDomainEl,
  dnsResultEl,
  dnsTransportEl,
  tableProblemSources,
  filterChipsEl,
  filterDomainEl,
  filterFromEl,
  filterHideMailboxNoiseEl,
  filterPanelEl,
  filterRangeEl,
  filterSearchEl,
  simulationModeEl,
  filterToEl,
  filterCustomWrap,
  filterDispositionEl,
  forensicBody,
  ipDetailBody,
  ipDetailDialog,
  reportsBody,
  scannerNoiseHostsEl,
  sectionJumpBarEl,
  summaryEl,
  tableFrom,
  tableIps,
  tableOrgs
} from './dom'
import {
  initDomainSettingsModalEvents,
  openDomainDkimSettings,
  openDomainSettingsScreenshotDemo,
  setDomainSettingsCallbacks
} from './domain-settings-modal'
import { escapeHtml, formatIpCellHtml, formatIpMetaHtml, formatRange } from './format'
import { invalidateIpMapSize, renderIpMap, setIpMapFilterHandler } from './ip-map'
import {
  configureNewSourcesView,
  refreshNewSourceIpMetadata,
  renderNewSendingSourcesBanner
} from './new-sources-view'
import {
  findSpfPrefixesForDomain,
  problemSourceIgnoreKey,
  readIgnoredProblemSourceKeys,
  writeIgnoredProblemSourceKeys
} from './problem-source-state'
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
import { initTlsRptDetailEvents, renderTlsRpt } from './tlsrpt-view'
import { readCollapsedWidgetIds, writeCollapsedWidgetIds } from './widget-state'

export {
  openDiagnosis,
  openDomainSettingsScreenshotDemo,
  refreshDomainHealth,
  renderDomainAmpel,
  syncDomainAmpelSelection
}

const collapsedWidgetIds = readCollapsedWidgetIds(window.localStorage)
const userToggledWidgets = new Set<string>()

function isWidgetCollapsed(widgetId: string): boolean {
  return collapsedWidgetIds.has(widgetId)
}

function setWidgetCollapsed(widgetId: string, collapsed: boolean): void {
  if (collapsed) collapsedWidgetIds.add(widgetId)
  else collapsedWidgetIds.delete(widgetId)
  writeCollapsedWidgetIds(window.localStorage, collapsedWidgetIds)
}

function syncWidgetCollapsedDom(widgetId: string): void {
  const widget = document.querySelector<HTMLElement>(`.dashboard-widget[data-widget="${widgetId}"]`)
  if (!widget) return
  const collapsed = isWidgetCollapsed(widgetId)
  widget.classList.toggle('is-collapsed', collapsed)
  const button = widget.querySelector<HTMLButtonElement>(`[data-widget-collapse-id="${widgetId}"]`)
  if (button) updateWidgetToggle(button, collapsed)
  const title = widget.querySelector<HTMLHeadingElement>(':scope > .widget-heading h2')
  title?.setAttribute('aria-expanded', String(!collapsed))
}

/** Expand a dashboard widget if collapsed and scroll it smoothly into view. */
export function jumpToWidget(widgetId: string, subSelector?: string): void {
  const widget = document.querySelector<HTMLElement>(`.dashboard-widget[data-widget="${widgetId}"]`)
  if (!widget) return
  if (isWidgetCollapsed(widgetId)) {
    userToggledWidgets.add(widgetId)
    setWidgetCollapsed(widgetId, false)
    syncWidgetCollapsedDom(widgetId)
    refreshExpandedWidgetLayout(widgetId)
  }
  const target = (subSelector ? widget.querySelector<HTMLElement>(subSelector) : null) ?? widget
  requestAnimationFrame(() => {
    const top = target.getBoundingClientRect().top + window.scrollY - 84
    window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' })
  })
}

function autoSyncEmptyAuxiliaryWidgets(result: AnalyzeResult | null): void {
  if (!result) return
  const aux: Array<{ id: string; count: number }> = [
    { id: 'forensic', count: result.forensicReports?.length ?? 0 },
    { id: 'tlsrpt', count: result.tlsRptReports?.length ?? 0 }
  ]
  for (const { id, count } of aux) {
    if (userToggledWidgets.has(id)) continue
    const shouldCollapse = count === 0
    if (isWidgetCollapsed(id) !== shouldCollapse) {
      setWidgetCollapsed(id, shouldCollapse)
      syncWidgetCollapsedDom(id)
    }
  }
}

function updateWidgetToggle(button: HTMLButtonElement, collapsed: boolean): void {
  const labelKey: MessageKey = collapsed ? 'widget.expand' : 'widget.collapse'
  const label = t(labelKey)
  button.dataset.i18nTitle = labelKey
  button.dataset.i18nAria = labelKey
  button.title = label
  button.setAttribute('aria-label', label)
  button.setAttribute('aria-expanded', String(!collapsed))
  button.textContent = collapsed ? '▾' : '▴'
}

function refreshExpandedWidgetLayout(widgetId: string): void {
  requestAnimationFrame(() => {
    if (widgetId === 'ipMap') invalidateIpMapSize()
    window.dispatchEvent(new Event('resize'))
  })
}

function isInteractiveWidgetHeadingTarget(target: EventTarget | null): boolean {
  return (
    target instanceof Element &&
    target.closest('button, a, input, select, textarea, .widget-info') !== null
  )
}

function initWidgetTitleKeyboard(title: HTMLHeadingElement, toggleWidget: () => void): void {
  title.tabIndex = 0
  title.setAttribute('role', 'button')
  title.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return
    event.preventDefault()
    toggleWidget()
  })
}

export function refreshWidgetToggleLocale(): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-widget-collapse-id]')) {
    updateWidgetToggle(button, isWidgetCollapsed(button.dataset.widgetCollapseId ?? ''))
  }
}

function initCollapsibleWidgets(): void {
  for (const widget of document.querySelectorAll<HTMLElement>('.dashboard-widget[data-widget]')) {
    const widgetId = widget.dataset.widget
    const heading = widget.querySelector<HTMLElement>(':scope > .widget-heading')
    const title = heading?.querySelector<HTMLHeadingElement>('h2')
    if (!widgetId || !heading || !title) continue

    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'btn secondary widget-collapse-toggle'
    button.dataset.widgetCollapseId = widgetId
    heading.classList.add('widget-heading-clickable')
    const applyState = (): void => {
      const collapsed = isWidgetCollapsed(widgetId)
      widget.classList.toggle('is-collapsed', collapsed)
      updateWidgetToggle(button, collapsed)
      title.setAttribute('aria-expanded', String(!collapsed))
    }
    const toggleWidget = (): void => {
      userToggledWidgets.add(widgetId)
      const collapsed = !isWidgetCollapsed(widgetId)
      setWidgetCollapsed(widgetId, collapsed)
      applyState()
      if (!collapsed) refreshExpandedWidgetLayout(widgetId)
    }
    button.addEventListener('click', toggleWidget)
    heading.addEventListener('click', (event) => {
      if (!isInteractiveWidgetHeadingTarget(event.target)) toggleWidget()
    })
    initWidgetTitleKeyboard(title, toggleWidget)
    heading.appendChild(button)
    applyState()
  }
}

function computePreviousPeriodDelta(current: AnalyzeResult | null): {
  passRateDiff: number | null
  failingDiff: number | null
} {
  const preset = filterRangeEl.value
  const days = preset === '7' ? 7 : preset === '30' ? 30 : preset === '90' ? 90 : 0
  if (!current || !state.fullResult || days <= 0 || current.aggregate.total === 0) {
    return { passRateDiff: null, failingDiff: null }
  }
  const now = new Date()
  const fmt = (d: Date): string => d.toISOString().slice(0, 10)
  const prevEnd = new Date(now.getTime() - days * 86_400_000)
  const prevStart = new Date(now.getTime() - 2 * days * 86_400_000)

  const simulated = simulationInput(state.fullResult)
  const hideMailboxNoise = filterHideMailboxNoiseEl.checked
  const scannerNoiseIps = collectScannerNoiseIps()
  const prevResult = applyDashboardFilter(simulated.result, {
    range: 'custom',
    from: fmt(prevStart),
    to: fmt(prevEnd),
    domain: filterDomainEl.value,
    disposition: normalizeDispositionFilter(filterDispositionEl.value),
    org: state.drill.org,
    sourceIp: state.drill.sourceIp,
    headerFrom: state.drill.headerFrom,
    hideMailboxNoise,
    mailboxIps: hideMailboxNoise ? collectMailboxIps() : undefined,
    mailboxNoiseProviders: enabledMailboxNoiseProviders(),
    scannerNoiseIps: scannerNoiseIps.size ? scannerNoiseIps : undefined
  })

  if (prevResult.aggregate.total === 0) {
    return { passRateDiff: null, failingDiff: null }
  }
  const passRateDiff =
    Math.round((current.aggregate.passRate - prevResult.aggregate.passRate) * 10) / 10
  const failingDiff = current.aggregate.failing - prevResult.aggregate.failing
  return { passRateDiff, failingDiff }
}

function renderDeltaBadge(
  key: 'passRate' | 'failing',
  diff: number | null,
  invertGood = false
): void {
  const el = document.querySelector<HTMLElement>(`[data-delta="${key}"]`)
  if (!el) return
  if (diff == null || diff === 0) {
    el.classList.add('hidden')
    el.textContent = ''
    return
  }
  const sign = diff > 0 ? '+' : ''
  const formatted = key === 'passRate' ? `${sign}${diff.toFixed(1)}%` : `${sign}${diff}`
  const isGood = invertGood ? diff < 0 : diff > 0
  el.textContent = formatted
  el.className = `stat-delta ${isGood ? 'ok' : 'bad'}`
  el.title = t('kpi.deltaVsPrev', { delta: formatted })
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
  const { passRateDiff, failingDiff } = computePreviousPeriodDelta(result)
  renderDeltaBadge('passRate', passRateDiff, false)
  renderDeltaBadge('failing', failingDiff, true)
}

function bindIpDetailButtons(root: ParentNode): void {
  for (const btn of root.querySelectorAll<HTMLButtonElement>('[data-ip-detail]')) {
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation()
      openIpDetail(btn.dataset.ipDetail ?? '')
    })
  }
}

function bindDiagnoseButtons(root: ParentNode): void {
  for (const btn of root.querySelectorAll<HTMLButtonElement>('[data-diagnose]')) {
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation()
      const ips = (btn.dataset.diagnose ?? '').split(',').filter(Boolean)
      openDiagnosis(ips)
    })
  }
}

/** Drop cached SPF marks (e.g. on account switch) so badges never use another account's expand. */
export function clearSpfMarks(): void {
  state.spfExpandToken++
  state.spfPrefixes = []
  state.spfPrefixesByDomain.clear()
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
  state.spfPrefixesByDomain.clear()
  if (!targets.length) {
    renderAfterSpfMarksUpdate()
    return
  }
  const cidrs = new Set<string>()
  const prefixesByDomain = new Map<string, CloudPrefix[]>()
  await Promise.all(
    targets.map(async (domain) => {
      try {
        const result = await window.api.expandSpf(domain)
        for (const c of result.cidrs) cidrs.add(c)
        prefixesByDomain.set(domain, parseAuthorizedSenderPrefixes(result.cidrs))
      } catch {
        // ignore per-domain SPF expand failures
      }
    })
  )
  if (token !== state.spfExpandToken) return
  state.spfPrefixes = parseAuthorizedSenderPrefixes([...cidrs])
  state.spfPrefixesByDomain = prefixesByDomain
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

let cachedDomainsResult: AnalyzeResult | null = null
let cachedDomainsByIp = new Map<string, string[]>()
const ipSearchTextCache = new Map<string, string>()
const reportSearchCache = new WeakMap<ReportRow, { text: string; ips: string[] }>()

function ensureDomainsByIpCache(): Map<string, string[]> {
  if (cachedDomainsResult === state.fullResult) return cachedDomainsByIp
  cachedDomainsResult = state.fullResult
  cachedDomainsByIp = new Map()
  ipSearchTextCache.clear()
  const sets = new Map<string, Set<string>>()
  for (const report of state.fullResult?.reports ?? []) {
    for (const record of report.records) {
      if (!record.sourceIp) continue
      const dom = record.headerFrom || report.domain
      if (!dom) continue
      let set = sets.get(record.sourceIp)
      if (!set) {
        set = new Set()
        sets.set(record.sourceIp, set)
      }
      set.add(dom)
    }
  }
  for (const [ip, set] of sets) {
    cachedDomainsByIp.set(ip, [...set])
  }
  return cachedDomainsByIp
}

function sendingDomainsForIp(ip: string): string[] {
  return ensureDomainsByIpCache().get(ip) ?? []
}

function activeSearchTokens(): string[] {
  const q = state.searchQuery.trim().toLowerCase()
  if (!q) return []
  return q.split(/\s+/).filter(Boolean)
}

function ipSearchString(ip: string): string {
  ensureDomainsByIpCache()
  const cached = ipSearchTextCache.get(ip)
  if (cached !== undefined) return cached
  const info = state.ipLabelCache.get(ip)
  const str = [
    ip,
    ...sendingDomainsForIp(ip),
    info?.ptr ?? '',
    info?.provider ?? '',
    info?.asOrg ?? '',
    info?.cloudProvider ?? '',
    info?.country ?? '',
    info?.countryCode ?? '',
    info?.city ?? '',
    info?.asn != null ? `as${info.asn}` : ''
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
  ipSearchTextCache.set(ip, str)
  return str
}

function filterBucketRows(rows: NamedBucket[], withIpMeta = false): NamedBucket[] {
  const tokens = activeSearchTokens()
  if (tokens.length === 0) return rows
  return rows.filter((r) => {
    const base = `${r.name} ${r.provider ?? ''} ${r.label ?? ''}`.toLowerCase()
    const hay = withIpMeta ? `${base} ${ipSearchString(r.name)}` : base
    return tokens.every((token) => hay.includes(token))
  })
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
  const cols = options.withIpMeta ? 4 : 3
  const filteredRows = filterBucketRows(rows, Boolean(options.withIpMeta))
  if (!filteredRows.length) {
    tbody.innerHTML = `<tr class="empty"><td colspan="${cols}">${escapeHtml(t('table.noData'))}</td></tr>`
    return
  }
  const sorted = options.sort
    ? sortRows(filteredRows, options.sort, (a, b, key) =>
        compareBucket(a, b, key, Boolean(options.withIpMeta))
      )
    : filteredRows
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
        const ipMeta = formatIpMetaHtml(r.name, r.provider, r.label, {
          sendingDomains: sendingDomainsForIp(r.name)
        })
        return `
      <tr data-name="${escapeHtml(r.name)}"${ipMeta ? ' class="has-ip-meta"' : ''}${clickAttrs}>
        <td class="ip-col">${formatIpCellHtml(r.name, r.provider, r.label, { includeMeta: false })}</td>
        <td>${r.count}</td>
        <td>
          <span class="rate-bar"><span style="width:${Math.min(100, r.passRate)}%"></span></span>
          ${r.passRate.toFixed(1)}%
        </td>
        <td>
          <span class="rate-bar"><span style="width:${r.count ? Math.min(100, (r.delivered / r.count) * 100) : 0}%"></span></span>
          ${r.count ? ((r.delivered / r.count) * 100).toFixed(1) : '0.0'}%
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
  { key: 'dkim', firstDir: 'desc' },
  { key: null }
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

type DisplayCategory = FailCategory | 'ownSender' | 'misaligned'

function spfPrefixesForDomain(domain: string | null): CloudPrefix[] {
  return findSpfPrefixesForDomain(state.spfPrefixesByDomain, domain)
}

function refineCategoryForDomain(
  base: FailCategory,
  ips: string[],
  domain: string | null
): DisplayCategory {
  if (base === 'forwarder') return base
  const prefixes = spfPrefixesForDomain(domain)
  return ips.some((ip) => isAuthorizedSender(ip, prefixes)) ? 'ownSender' : base
}

function problemCategory(row: ProblemSourceRow): DisplayCategory {
  if (row.category !== 'forwarder' && ((row.spfAuthPass ?? 0) > 0 || (row.dkimAuthPass ?? 0) > 0)) {
    return 'misaligned'
  }
  return refineCategoryForDomain(
    row.category ?? 'unauthenticated',
    [row.sourceIp, ...(row.extraIps ?? [])],
    row.headerFrom
  )
}

function problemCategoryLabel(row: ProblemSourceRow): string {
  return t(`problems.cat.${problemCategory(row)}`)
}

const CATEGORY_BADGE_CLASS: Record<DisplayCategory, string> = {
  forwarder: 'badge',
  thirdParty: 'badge cloud',
  broken: 'badge warn',
  ownSender: 'badge warn',
  misaligned: 'badge warn',
  unauthenticated: 'badge bad'
}

function categoryBadgeHtml(category: DisplayCategory): string {
  const hint = t(`problems.catHint.${category}`)
  return `<span class="${CATEGORY_BADGE_CLASS[category]}" title="${escapeHtml(hint)}">${escapeHtml(
    t(`problems.cat.${category}`)
  )}</span>`
}

function problemCategoryHtml(row: ProblemSourceRow): string {
  const ips = [row.sourceIp, ...(row.extraIps ?? [])]
  const diagnoseBtn = `<button type="button" class="diagnose-btn" data-diagnose="${escapeHtml(ips.join(','))}" title="${escapeHtml(t('problems.diagnoseHint'))}" aria-label="${escapeHtml(t('problems.diagnoseHint'))}">?</button>`
  return `${categoryBadgeHtml(problemCategory(row))}${diagnoseBtn}`
}

function problemActionHtml(row: ProblemSourceRow): string {
  const ips = [row.sourceIp, ...(row.extraIps ?? [])]
  const label = escapeHtml(t('problems.ignore'))
  return `<button type="button" class="btn secondary problem-ignore-btn" data-ignore-problem="${escapeHtml(ips.join(','))}" data-ignore-from="${escapeHtml(row.headerFrom ?? '')}" title="${label}">${label}</button>`
}

function renderProblemSources(rows: ProblemSourceRow[]): void {
  if (!tableProblemSources) return
  const accountId = state.settings?.activeAccountId ?? null
  const ignored = readIgnoredProblemSourceKeys(window.localStorage, accountId)
  btnResetIgnoredProblemSources?.classList.toggle('hidden', ignored.size === 0)
  const visibleRows = rows.filter(
    (row) => !ignored.has(problemSourceIgnoreKey(row.sourceIp, row.headerFrom))
  )
  const tokens = activeSearchTokens()
  const groupedAll = groupProblemSources(visibleRows, (ip) => state.ipLabelCache.get(ip))
  const grouped = (
    tokens.length === 0
      ? groupedAll
      : groupedAll.filter((r) => {
          const allIps = [r.sourceIp, ...(r.extraIps ?? [])]
          const base = `${r.headerFrom ?? ''} ${problemCategoryLabel(r)}`.toLowerCase()
          return tokens.every(
            (token) =>
              base.includes(token) || allIps.some((ip) => ipSearchString(ip).includes(token))
          )
        })
  ).slice(0, 40)
  setJumpBadgeCount('problemSources', grouped.length, grouped.length > 0)
  if (!grouped.length) {
    tableProblemSources.innerHTML = `<tr class="empty"><td colspan="7">${escapeHtml(t('problems.empty'))}</td></tr>`
    return
  }
  tableProblemSources.innerHTML = sortRows(grouped, sortProblems, compareProblemSource)
    .map((r) => {
      const groupCount = 1 + (r.extraIps?.length ?? 0)
      const filterValue = problemSourceFilterValue(r)
      const ipMeta = formatIpMetaHtml(r.sourceIp, null, null, {
        groupedIpCount: groupCount,
        spfPrefixes: spfPrefixesForDomain(r.headerFrom),
        spfDomain: r.headerFrom,
        sendingDomain: r.headerFrom
      })
      const rowClass = ipMeta ? 'has-ip-meta' : ''
      return `
      <tr data-name="${escapeHtml(filterValue)}" class="${rowClass}" tabindex="0" title="${escapeHtml(t('filter.clickToFilter'))}">
        <td class="ip-col">${formatIpCellHtml(r.sourceIp, null, null, { includeMeta: false })}</td>
        <td class="mono-from" title="${escapeHtml(r.headerFrom ?? '')}">${escapeHtml(r.headerFrom ?? '—')}</td>
        <td class="cat-col">${problemCategoryHtml(r)}</td>
        <td>${r.count}</td>
        <td>${r.spfFail}</td>
        <td>${r.dkimFail}</td>
        <td class="problem-action-col">${problemActionHtml(r)}</td>
      </tr>
      ${ipMeta ? `<tr class="ip-meta-row" data-name="${escapeHtml(filterValue)}" title="${escapeHtml(t('filter.clickToFilter'))}"><td colspan="7">${ipMeta}</td></tr>` : ''}`
    })
    .join('')

  for (const tr of tableProblemSources.querySelectorAll<HTMLTableRowElement>('tr[data-name]')) {
    tr.addEventListener('click', (ev) => {
      const target = ev.target as HTMLElement
      if (
        target.closest('[data-ip-detail]') ||
        target.closest('[data-diagnose]') ||
        target.closest('[data-ignore-problem]')
      ) {
        return
      }
      setDrillFilter('sourceIp', tr.dataset.name ?? '')
    })
  }
  bindIpDetailButtons(tableProblemSources)
  bindDiagnoseButtons(tableProblemSources)
  for (const btn of tableProblemSources.querySelectorAll<HTMLButtonElement>(
    '[data-ignore-problem]'
  )) {
    btn.addEventListener('click', (event) => {
      event.stopPropagation()
      const ips = (btn.dataset.ignoreProblem ?? '').split(',').filter(Boolean)
      const headerFrom = btn.dataset.ignoreFrom ?? ''
      const source = ips.length === 1 ? ips[0] : t('problems.ipGroup', { count: ips.length })
      if (!confirm(t('problems.ignoreConfirm', { source, domain: headerFrom || '—' }))) return
      const next = readIgnoredProblemSourceKeys(window.localStorage, accountId)
      for (const ip of ips) next.add(problemSourceIgnoreKey(ip, headerFrom))
      writeIgnoredProblemSourceKeys(window.localStorage, accountId, next)
      renderProblemSources(rows)
    })
  }
}

function renderFilterChips(): void {
  const chips: Array<{ key: keyof DrillFilters | 'search'; label: string; value: string }> = []
  if (state.drill.org) chips.push({ key: 'org', label: t('table.org'), value: state.drill.org })
  if (state.drill.sourceIp)
    chips.push({
      key: 'sourceIp',
      label: t('detail.ip'),
      value: formatSourceIpChip(state.drill.sourceIp)
    })
  if (state.drill.headerFrom)
    chips.push({ key: 'headerFrom', label: t('detail.from'), value: state.drill.headerFrom })
  if (state.searchQuery.trim())
    chips.push({
      key: 'search',
      label: t('filter.searchChip'),
      value: state.searchQuery.trim()
    })

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
      const key = btn.dataset.chip as keyof DrillFilters | 'search'
      if (key === 'search') {
        state.searchQuery = ''
        if (filterSearchEl) filterSearchEl.value = ''
      } else {
        delete state.drill[key]
      }
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
    simulationModeEl.value !== 'off' ||
    filterHideMailboxNoiseEl.checked ||
    Boolean(state.searchQuery.trim()) ||
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
  simulationModeEl.value = 'off'
  filterHideMailboxNoiseEl.checked = false
  state.searchQuery = ''
  if (filterSearchEl) filterSearchEl.value = ''
  rangeBeforeDayFilter = null
  clearDrill()
  writeDashboardUiState(window.localStorage, {
    range: DEFAULT_DATE_RANGE,
    disposition: 'all',
    domain: ''
  })
  syncCustomRangeVisibility()
  applyView()
  if (noiseWasOn) void persistHideMailboxNoise()
}

function normalizeSimulationMode(value: string): RolloutSimulationMode {
  return value === 'reject' || value === 'strictDkim' || value === 'subdomainReject' ? value : 'off'
}

function simulationInput(result: AnalyzeResult): {
  result: AnalyzeResult
  mode: RolloutSimulationMode
  domain: string
} {
  const mode = normalizeSimulationMode(simulationModeEl.value)
  const domain = filterDomainEl.value.trim().toLowerCase()
  if (mode === 'off' || !domain) return { result, mode: 'off', domain: '' }
  const simulatedReports = simulateRolloutReports(result.reports, domain, mode)
  if (simulatedReports === result.reports) return { result, mode: 'off', domain: '' }
  const simulatedResult = analyzeFromReports(simulatedReports, {
    skipped: result.skipped,
    errors: result.errors,
    fromCache: result.fromCache,
    newReports: result.newReports,
    newForensicReports: result.newForensicReports,
    forensicReports: result.forensicReports,
    newTlsRptReports: result.newTlsRptReports,
    tlsRptReports: result.tlsRptReports
  })
  return {
    result: simulatedResult,
    mode,
    domain
  }
}

function syncSimulationUi(mode: RolloutSimulationMode, domain: string): void {
  state.simulationMode = mode
  state.simulationDomain = domain
  const active = mode !== 'off' && Boolean(domain)
  document.body.classList.toggle('simulation-mode', active)
}

function ensureSimulationDomain(): void {
  if (simulationModeEl.value === 'off' || filterDomainEl.value) return
  const domain = state.fullResult?.aggregate.domains[0] ?? ''
  if (domain) filterDomainEl.value = domain
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

function syncIpDetailNoiseButton(): void {
  if (!btnIpNoise) return
  const ip = state.selectedDetailIp
  if (!ip) {
    btnIpNoise.disabled = true
    return
  }
  const info = state.ipLabelCache.get(ip)
  const listed = matchesScannerNoise(ip, info?.ptr, scannerNoiseMatchers())
  const entry = suggestScannerNoiseEntry(info?.ptr, ip, info?.senderKind)
  btnIpNoise.disabled = listed || !entry
  btnIpNoise.textContent = listed ? t('ipNoise.listed') : t('ipNoise.add')
  btnIpNoise.title = listed ? t('ipNoise.listed') : t('ipNoise.addNamed', { entry: entry ?? ip })
}

export function openIpDetail(ip: string): void {
  if (!ip) return
  state.selectedDetailIp = ip
  renderIpDetailBody(ip)
  syncIpDetailNoiseButton()
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
  for (const group of state.fullResult?.newSendingSources ?? []) {
    for (const ip of group.ips) pushIp(ip)
  }
  for (const row of d.bySourceIp) pushIp(row.name)
  for (const row of d.problemSources ?? []) pushIp(row.sourceIp)
  void enrichIpLabels(enrichIps)
  // Ampel ignores the dashboard date filter — always last N days of fullResult.
  void refreshDomainHealth(state.fullResult)
}

function enabledMailboxNoiseProviders(): ReturnType<typeof parseMailboxNoiseProviders> {
  const text = state.settings?.global.mailboxNoiseProviders ?? DEFAULT_MAILBOX_NOISE_PROVIDERS
  return parseMailboxNoiseProviders(text)
}

function collectMailboxIps(): Set<string> {
  const enabled = enabledMailboxNoiseProviders()
  const set = new Set<string>()
  for (const [ip, info] of state.ipLabelCache) {
    if (isMailboxIpInfo(info, enabled)) set.add(ip)
  }
  return set
}

function scannerNoiseMatchers(): ReturnType<typeof parseScannerNoiseHosts> {
  const text = state.settings?.global.scannerNoiseHosts ?? DEFAULT_SCANNER_NOISE_HOSTS
  return parseScannerNoiseHosts(text)
}

function collectScannerNoiseIps(): Set<string> {
  const matchers = scannerNoiseMatchers()
  const set = new Set<string>()
  const consider = (ip: string): void => {
    if (!ip || set.has(ip)) return
    const info = state.ipLabelCache.get(ip)
    if (matchesScannerNoise(ip, info?.ptr, matchers)) set.add(ip)
  }
  for (const [ip] of state.ipLabelCache) consider(ip)
  if (state.fullResult) {
    for (const report of state.fullResult.reports) {
      for (const rec of report.records) consider(rec.sourceIp)
    }
  }
  return set
}

async function enrichIpLabels(ips: string[]): Promise<void> {
  // When the mailbox-noise filter is on, resolve those candidates first (up to 40).
  const missing = ips.filter((ip) => !state.ipLabelCache.has(ip)).slice(0, 40)
  if (!missing.length) return
  try {
    const infos = await window.api.resolveIps(missing)
    const matchers = scannerNoiseMatchers()
    const mailboxProviders = enabledMailboxNoiseProviders()
    let foundMailbox = false
    let foundScannerNoise = false
    for (const info of infos) {
      state.ipLabelCache.set(info.ip, info)
      ipSearchTextCache.delete(info.ip)
      if (isMailboxIpInfo(info, mailboxProviders)) foundMailbox = true
      if (isScannerNoiseIpInfo(info, matchers)) foundScannerNoise = true
    }
    // Re-filter once noise IPs are known so KPIs/charts/problem sources update together.
    if (foundScannerNoise || (foundMailbox && filterHideMailboxNoiseEl.checked)) {
      applyView()
      renderNewSendingSourcesBanner(state.fullResult)
      return
    }
    if (state.viewResult) {
      renderIpTable(state.viewResult.dashboard.bySourceIp)
      renderProblemSources(state.viewResult.dashboard.problemSources ?? [])
      renderIpMap(state.viewResult.dashboard.bySourceIp)
    }
    refreshNewSourceIpMetadata()
    // Refresh open record details so geo/ASN/DNSBL appear once enrichment lands.
    if (state.selectedReportId && state.viewResult) {
      const selected =
        state.viewResult.reports.find((r) => r.reportId === state.selectedReportId) ?? null
      if (selected) renderDetail(selected)
    }
    if (state.selectedDetailIp && ipDetailDialog.open) {
      renderIpDetailBody(state.selectedDetailIp)
      syncIpDetailNoiseButton()
    }
  } catch {
    // Enrichment ist optional.
  }
}

function setJumpBadgeCount(widgetId: string, count: number, highlightWarn = false): void {
  const badge = sectionJumpBarEl?.querySelector<HTMLElement>(`[data-jump-count="${widgetId}"]`)
  const pill = sectionJumpBarEl?.querySelector<HTMLElement>(`[data-jump-widget="${widgetId}"]`)
  if (badge) {
    badge.textContent = count > 0 ? String(count) : ''
    badge.classList.toggle('hidden', count <= 0)
  }
  pill?.classList.toggle('has-alert', highlightWarn && count > 0)
}

function updateJumpBarBadges(result: AnalyzeResult | null): void {
  const domainCount = state.domainHealthCache.length || (result?.aggregate.domains.length ?? 0)
  setJumpBadgeCount('health', domainCount)
  setJumpBadgeCount('tables', filterBucketRows(result?.dashboard.bySourceIp ?? [], true).length)
  setJumpBadgeCount('reports', filterReportRows(result?.reports ?? []).length)
  setJumpBadgeCount('forensic', filterForensicRows(result?.forensicReports ?? []).length)
  setJumpBadgeCount('tlsrpt', result?.tlsRptReports?.length ?? 0)
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
            refineCategoryForDomain(
              categorizeFailure(r, report.domain),
              [r.sourceIp].filter(Boolean),
              r.headerFrom || report.domain
            )
          )
      const reasonCell = [cause, reasons].filter(Boolean).join('<br />') || '—'
      const ipMeta = formatIpMetaHtml(r.sourceIp, null, null, {
        sendingDomain: r.headerFrom || report.domain
      })
      const ipAttr = escapeHtml(r.sourceIp)
      return `
      <tr data-name="${ipAttr}"${ipMeta ? ' class="has-ip-meta"' : ''}>
        <td class="ip-col">${formatIpCellHtml(r.sourceIp, null, null, { includeMeta: false })}</td>
        <td>${r.count}</td>
        <td>${escapeHtml(r.disposition ?? '—')}</td>
        <td class="${r.dkimResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.dkimResult ?? '—')}</td>
        <td class="${r.spfResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.spfResult ?? '—')}</td>
        <td class="${r.passesDmarc ? 'pass' : 'fail'}">${r.passesDmarc ? 'pass' : 'fail'}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
        <td class="reasons">${reasonCell}</td>
      </tr>
      ${ipMeta ? `<tr class="ip-meta-row" data-name="${ipAttr}"><td colspan="8">${ipMeta}</td></tr>` : ''}`
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

function filterForensicRows(rows: ForensicReportRow[]): ForensicReportRow[] {
  const tokens = activeSearchTokens()
  if (tokens.length === 0) return rows
  return rows.filter((r) => {
    const base = [
      r.reportedDomain,
      r.sourceIp,
      r.orgName,
      r.headerFrom,
      r.envelopeFrom,
      r.authFailure,
      r.subject,
      r.feedbackType
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
    const hay = r.sourceIp ? `${base} ${ipSearchString(r.sourceIp)}` : base
    return tokens.every((token) => hay.includes(token))
  })
}

function renderForensic(result: AnalyzeResult | null): void {
  const rows = filterForensicRows(result?.forensicReports ?? [])
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

function getReportSearchEntry(r: ReportRow): { text: string; ips: string[] } {
  const cached = reportSearchCache.get(r)
  if (cached) return cached
  const parts = new Set<string>()
  const ips = new Set<string>()
  if (r.reportId) parts.add(r.reportId.toLowerCase())
  if (r.orgName) parts.add(r.orgName.toLowerCase())
  if (r.domain) parts.add(r.domain.toLowerCase())
  if (r.policyP) parts.add(r.policyP.toLowerCase())
  for (const rec of r.records) {
    if (rec.sourceIp) ips.add(rec.sourceIp)
    if (rec.headerFrom) parts.add(rec.headerFrom.toLowerCase())
    if (rec.dkimDomain) parts.add(rec.dkimDomain.toLowerCase())
    if (rec.spfDomain) parts.add(rec.spfDomain.toLowerCase())
  }
  const entry = { text: [...parts].join(' '), ips: [...ips] }
  reportSearchCache.set(r, entry)
  return entry
}

function filterReportRows(rows: ReportRow[]): ReportRow[] {
  const tokens = activeSearchTokens()
  if (tokens.length === 0) return rows
  return rows.filter((r) => {
    const entry = getReportSearchEntry(r)
    return tokens.every(
      (token) =>
        entry.text.includes(token) || entry.ips.some((ip) => ipSearchString(ip).includes(token))
    )
  })
}

export function renderReports(result: AnalyzeResult | null): void {
  const filtered = result ? filterReportRows(result.reports) : []
  const rows = filtered.length ? sortRows(filtered, sortReports, compareReport) : []
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
  const current = filterDomainEl.value || readDashboardUiState(window.localStorage).domain
  const domains = [
    ...new Set(
      [
        ...(result?.aggregate.domains ?? []),
        ...(result?.forensicReports ?? []).map((report) => report.reportedDomain ?? ''),
        ...(result?.tlsRptReports ?? []).flatMap((report) =>
          report.policies.map((policy) => policy.policyDomain)
        )
      ]
        .map((domain) => domain.trim())
        .filter(Boolean)
    )
  ]
  filterDomainEl.innerHTML =
    `<option value="">${escapeHtml(t('filter.allDomains'))}</option>` +
    domains.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('')
  const match = current
    ? domains.find((d) => d.toLowerCase() === current.trim().toLowerCase())
    : undefined
  filterDomainEl.value = match ?? ''
}

/** A single IPv4/IPv6 address as its narrowest CIDR, for prefilling the inventory form. */
function singleIpCidr(ip: string): string {
  return ip.includes(':') ? `${ip}/128` : `${ip}/32`
}

setAmpelDomainChangedCallback(() => {
  writeDashboardUiState(window.localStorage, { domain: filterDomainEl.value })
  applyView()
})

configureNewSourcesView({
  domainsForIp: (ip) => domainsForIp(ip),
  setDrillFilter,
  openIpDetail,
  addIpToScannerNoise: (ip) => addIpToScannerNoise(ip),
  addIpsToScannerNoise: (ips) => addIpsToScannerNoise(ips),
  collectScannerNoiseIps,
  collectMailboxIps,
  enabledMailboxNoiseProviders,
  isWidgetCollapsed,
  setWidgetCollapsed,
  updateWidgetToggle,
  isInteractiveWidgetHeadingTarget,
  initWidgetTitleKeyboard
})

let lastSyncedFilterDomain: string | null = null

function syncDnsDialogDomain(): void {
  const selected = filterDomainEl.value.trim()
  if (lastSyncedFilterDomain === selected || dnsDialog?.open) return
  lastSyncedFilterDomain = selected
  if (dnsDomainEl.value.trim().toLowerCase() !== selected.toLowerCase()) {
    dnsDomainEl.value = selected
    dnsResultEl.textContent = ''
    dnsResultEl.className = 'dns-result muted hidden'
    dnsTransportEl.innerHTML = ''
    dnsTransportEl.classList.add('hidden')
  }
}

export function applyView(): void {
  renderFilterChips()
  syncFilterResetButton()
  syncDomainAmpelSelection()
  syncDnsDialogDomain()
  if (!state.fullResult) {
    state.viewResult = null
    state.spfExpandToken++
    state.spfPrefixes = []
    state.spfPrefixesByDomain.clear()
    updateSummary(null)
    renderDashboard(null)
    renderReports(null)
    renderForensic(null)
    renderTlsRpt(null)
    renderNewSendingSourcesBanner(null)
    updateJumpBarBadges(null)
    btnExport.disabled = true
    return
  }

  const simulated = simulationInput(state.fullResult)
  syncSimulationUi(simulated.mode, simulated.domain)
  const hideMailboxNoise = filterHideMailboxNoiseEl.checked
  const scannerNoiseIps = collectScannerNoiseIps()
  const mailboxNoiseProviders = enabledMailboxNoiseProviders()
  state.viewResult = applyDashboardFilter(simulated.result, {
    range: filterRangeEl.value as DateRangePreset,
    from: filterFromEl.value || undefined,
    to: filterToEl.value || undefined,
    domain: filterDomainEl.value,
    disposition: normalizeDispositionFilter(filterDispositionEl.value),
    org: state.drill.org,
    sourceIp: state.drill.sourceIp,
    headerFrom: state.drill.headerFrom,
    hideMailboxNoise,
    mailboxIps: hideMailboxNoise ? collectMailboxIps() : undefined,
    mailboxNoiseProviders,
    scannerNoiseIps: scannerNoiseIps.size ? scannerNoiseIps : undefined
  })
  autoSyncEmptyAuxiliaryWidgets(state.viewResult)
  updateSummary(state.viewResult)
  renderDashboard(state.viewResult)
  renderReports(state.viewResult)
  renderForensic(state.viewResult)
  renderTlsRpt(state.viewResult)
  updateJumpBarBadges(state.viewResult)
  btnExport.disabled =
    state.viewResult.reports.length === 0 && (state.viewResult.forensicReports?.length ?? 0) === 0
}

export function showResult(result: AnalyzeResult, statusMessage?: string): void {
  state.fullResult = result
  fillDomainFilter(result)
  applyView()
  renderNewSendingSourcesBanner(result)
  void refreshSendingServicesForMetadata()
  if (statusMessage) {
    setStatus(statusMessage, 'ok')
  } else {
    const skippedNote = result.skipped ? t('status.skippedPart', { count: result.skipped }) : ''
    const newNote =
      result.newReports != null ? t('status.newPart', { count: result.newReports }) : ''
    const tlsRptNote = result.newTlsRptReports
      ? t('status.newTlsRptPart', { count: result.newTlsRptReports })
      : ''
    const cacheNote = result.fromCache ? t('status.cachePart') : ''
    const sourceNote = result.newSourceIps?.length
      ? t('status.sourcePart', { count: result.newSourceIps.length })
      : ''
    setStatus(
      t('status.result', {
        reports: result.aggregate.reportCount,
        newNote,
        tlsRptNote,
        cacheNote,
        messages: result.aggregate.total,
        skippedNote,
        sourceNote
      }),
      'ok'
    )
  }
}

async function refreshSendingServicesForMetadata(): Promise<void> {
  try {
    state.sendingServices = await window.api.listSendingServices()
    if (!state.fullResult) return
    applyView()
    renderNewSendingSourcesBanner(state.fullResult)
    if (state.selectedReportId && state.viewResult) {
      const selected =
        state.viewResult.reports.find((r) => r.reportId === state.selectedReportId) ?? null
      renderDetail(selected)
    }
  } catch {
    // Das Dienstinventar ist optional fuer die Metadaten.
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
  const savedUi = readDashboardUiState(window.localStorage)
  filterRangeEl.value = savedUi.range
  filterDispositionEl.value = savedUi.disposition
  syncCustomRangeVisibility()

  initStickyFilter()
  initTables()
  initCollapsibleWidgets()
  setIpMapFilterHandler((ip) => setDrillFilter('sourceIp', ip))
  setVolumeDayClickHandler(filterVolumeByDay)

  btnCloseIpDetail.addEventListener('click', () => ipDetailDialog.close())
  setDomainSettingsCallbacks({
    onSendersChanged: () => {
      if (state.fullResult) {
        applyView()
        renderNewSendingSourcesBanner(state.fullResult)
      }
    },
    onDkimSaved: () => {
      void refreshDomainHealth(state.fullResult, { force: true })
    }
  })
  initDomainSettingsModalEvents()
  initDiagnosisModalEvents()
  initTlsRptDetailEvents()
  btnIpFilter.addEventListener('click', () => {
    if (!state.selectedDetailIp) return
    ipDetailDialog.close()
    setDrillFilter('sourceIp', state.selectedDetailIp)
  })
  btnIpNoise?.addEventListener('click', () => {
    void addIpToScannerNoise(state.selectedDetailIp ?? '')
  })
  initIpContextMenu()
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
    if (filterRangeEl.value !== 'custom') {
      writeDashboardUiState(window.localStorage, {
        range: filterRangeEl.value as DateRangePreset
      })
    }
    syncCustomRangeVisibility()
    applyView()
  })
  filterFromEl.addEventListener('change', () => applyView())
  filterToEl.addEventListener('change', () => applyView())
  filterDomainEl.addEventListener('change', () => {
    if (!filterDomainEl.value && simulationModeEl.value !== 'off') simulationModeEl.value = 'off'
    writeDashboardUiState(window.localStorage, { domain: filterDomainEl.value })
    applyView()
  })
  filterDispositionEl.addEventListener('change', () => {
    writeDashboardUiState(window.localStorage, {
      disposition: normalizeDispositionFilter(filterDispositionEl.value)
    })
    applyView()
  })
  simulationModeEl.addEventListener('change', () => {
    ensureSimulationDomain()
    applyView()
  })
  filterHideMailboxNoiseEl.addEventListener('change', () => {
    applyView()
    void persistHideMailboxNoise()
  })
  let searchDebounceTimer: ReturnType<typeof setTimeout> | null = null
  const applySearchOnly = (): void => {
    renderFilterChips()
    syncFilterResetButton()
    const res = state.viewResult
    const d = res?.dashboard
    renderBucketTable(tableOrgs, d?.byOrg ?? [], {
      sort: sortOrgs,
      onRowClick: (name) => setDrillFilter('org', name)
    })
    renderIpTable(d?.bySourceIp ?? [])
    renderBucketTable(tableFrom, d?.byHeaderFrom ?? [], {
      sort: sortFrom,
      onRowClick: (name) => setDrillFilter('headerFrom', name)
    })
    renderProblemSources(d?.problemSources ?? [])
    renderReports(res)
    renderForensic(res)
    updateJumpBarBadges(res)
  }

  filterSearchEl?.addEventListener('input', () => {
    state.searchQuery = filterSearchEl.value
    if (searchDebounceTimer) clearTimeout(searchDebounceTimer)
    searchDebounceTimer = setTimeout(() => {
      searchDebounceTimer = null
      applySearchOnly()
    }, 80)
  })
  filterSearchEl?.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && filterSearchEl.value) {
      event.preventDefault()
      event.stopPropagation()
      if (searchDebounceTimer) {
        clearTimeout(searchDebounceTimer)
        searchDebounceTimer = null
      }
      filterSearchEl.value = ''
      state.searchQuery = ''
      applySearchOnly()
    }
  })
  document.addEventListener('keydown', (event) => {
    if (!filterSearchEl) return
    if (document.querySelector('dialog[open]')) return
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f') {
      event.preventDefault()
      filterSearchEl.focus()
      filterSearchEl.select()
      return
    }
    if (
      event.key === '/' &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.altKey &&
      !(
        event.target instanceof HTMLInputElement ||
        event.target instanceof HTMLTextAreaElement ||
        event.target instanceof HTMLSelectElement
      )
    ) {
      event.preventDefault()
      filterSearchEl.focus()
      filterSearchEl.select()
    }
  })
  sectionJumpBarEl?.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null
    const btn = target?.closest<HTMLButtonElement>('[data-jump-widget]')
    if (!btn?.dataset.jumpWidget) return
    jumpToWidget(btn.dataset.jumpWidget)
  })
  const handleKpiAction = (action: string | undefined): void => {
    switch (action) {
      case 'reports':
        jumpToWidget('reports')
        break
      case 'messages':
        jumpToWidget('charts', '.volume-card')
        break
      case 'pass':
        jumpToWidget('tables')
        break
      case 'fail':
        jumpToWidget('problemSources')
        break
      case 'passRate':
        jumpToWidget('charts')
        break
      case 'range':
        filterRangeEl.focus()
        break
    }
  }
  summaryEl?.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null
    const card = target?.closest<HTMLElement>('[data-kpi-action]')
    if (card) handleKpiAction(card.dataset.kpiAction)
  })
  summaryEl?.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return
    const target = event.target instanceof Element ? event.target : null
    const card = target?.closest<HTMLElement>('[data-kpi-action]')
    if (!card) return
    event.preventDefault()
    handleKpiAction(card.dataset.kpiAction)
  })
  btnFilterReset.addEventListener('click', () => resetFilters())
  btnResetIgnoredProblemSources?.addEventListener('click', () => {
    writeIgnoredProblemSourceKeys(
      window.localStorage,
      state.settings?.activeAccountId ?? null,
      new Set()
    )
    renderProblemSources(state.viewResult?.dashboard.problemSources ?? [])
  })
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

let addingScannerNoise = false
let contextNoiseIp = ''

function hideIpContextMenu(): void {
  if (!ipContextMenu) return
  ipContextMenu.hidden = true
  contextNoiseIp = ''
}

function showIpContextMenu(ev: MouseEvent, ip: string): void {
  if (!ipContextMenu || !ipContextNoiseBtn || !ip) return
  ev.preventDefault()
  contextNoiseIp = ip
  const info = state.ipLabelCache.get(ip)
  const listed = matchesScannerNoise(ip, info?.ptr, scannerNoiseMatchers())
  const entry = suggestScannerNoiseEntry(info?.ptr, ip, info?.senderKind)
  ipContextNoiseBtn.disabled = listed || !entry
  ipContextNoiseBtn.textContent = listed ? t('ipNoise.listed') : t('ipNoise.add')
  ipContextMenu.hidden = false
  ipContextMenu.style.left = `${ev.clientX}px`
  ipContextMenu.style.top = `${ev.clientY}px`
  const rect = ipContextMenu.getBoundingClientRect()
  const dx = Math.min(0, window.innerWidth - 8 - rect.right)
  const dy = Math.min(0, window.innerHeight - 8 - rect.bottom)
  ipContextMenu.style.left = `${ev.clientX + dx}px`
  ipContextMenu.style.top = `${ev.clientY + dy}px`
}

function ipFromContextRow(target: EventTarget | null): string | null {
  const el = target instanceof Element ? target : (target as Node | null)?.parentElement
  const tr = el?.closest('tr[data-name]')
  if (!(tr instanceof HTMLTableRowElement)) return null
  const raw = tr.dataset.name?.trim() ?? ''
  return raw.split(',')[0]?.trim() || null
}

/** Distinct header-From domains seen for this IP across the loaded reports. */
function domainsForIp(ip: string): string[] {
  return [...sendingDomainsForIp(ip)].filter(Boolean).sort()
}

/** Opens domain settings with a sender-service draft from a known IP's context menu. */
function openSendingServiceFormForIp(ip: string): void {
  if (!ip) return
  const info = state.ipLabelCache.get(ip)
  const domains = domainsForIp(ip)
  const selectedDomain = domains.find(
    (domain) => domain.toLowerCase() === filterDomainEl.value.toLowerCase()
  )
  const domain = selectedDomain ?? domains[0]
  if (!domain) {
    setStatus(t('health.sendingServiceDomainRequired'))
    return
  }
  void openDomainDkimSettings(domain, {
    senderDraft: {
      provider: info?.provider ?? '',
      cidr: singleIpCidr(ip),
      asn: info?.asn ?? null,
      status: 'known'
    },
    onSenderSaved: async (savedService) => {
      if (savedService.status === 'known') {
        await window.api.acknowledgePendingSources([ip])
      }
    }
  })
}

function initIpContextMenu(): void {
  if (!ipContextMenu || !ipContextNoiseBtn) return
  for (const body of [tableIps, tableProblemSources, detailEl]) {
    body.addEventListener('contextmenu', (ev) => {
      const ip = ipFromContextRow(ev.target)
      if (!ip) return
      showIpContextMenu(ev, ip)
    })
  }
  ipContextNoiseBtn.addEventListener('click', () => {
    const ip = contextNoiseIp
    hideIpContextMenu()
    void addIpToScannerNoise(ip)
  })
  ipContextSendingServiceBtn?.addEventListener('click', () => {
    const ip = contextNoiseIp
    hideIpContextMenu()
    openSendingServiceFormForIp(ip)
  })
  document.addEventListener('pointerdown', (ev) => {
    if (ipContextMenu.hidden) return
    if (ipContextMenu.contains(ev.target as Node)) return
    hideIpContextMenu()
  })
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') hideIpContextMenu()
  })
  window.addEventListener('resize', hideIpContextMenu)
  document.addEventListener('scroll', hideIpContextMenu, true)
}

async function addIpsToScannerNoise(ips: readonly string[]): Promise<boolean> {
  if (!ips.length || !state.settings || addingScannerNoise) return false
  const entries = ips
    .map((ip) => {
      const info = state.ipLabelCache.get(ip)
      return suggestScannerNoiseEntry(info?.ptr, ip, info?.senderKind)
    })
    .filter((entry): entry is string => Boolean(entry))
  if (!entries.length) {
    setStatus(t('ipNoise.unavailable'), 'error')
    return false
  }
  const current = state.settings.global.scannerNoiseHosts ?? DEFAULT_SCANNER_NOISE_HOSTS
  const nextHosts = appendScannerNoiseEntries(current, entries)
  if (nextHosts === current) {
    setStatus(
      entries.length === 1
        ? t('ipNoise.already', { entry: entries[0] })
        : t('newSources.groupNoiseAlready'),
      'ok'
    )
    syncIpDetailNoiseButton()
    return true
  }
  addingScannerNoise = true
  try {
    const next = await window.api.saveGlobalSettings({
      ...state.settings.global,
      scannerNoiseHosts: nextHosts
    })
    state.settings = next
    scannerNoiseHostsEl.value = next.global.scannerNoiseHosts
    applyView()
    syncIpDetailNoiseButton()
    setStatus(
      entries.length === 1
        ? t('ipNoise.added', { entry: entries[0] })
        : t('newSources.groupNoiseAdded', { count: ips.length }),
      'ok'
    )
    return true
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
    return false
  } finally {
    addingScannerNoise = false
  }
}

async function addIpToScannerNoise(ip: string): Promise<boolean> {
  return addIpsToScannerNoise([ip])
}
