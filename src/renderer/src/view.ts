import {
  applyDashboardFilter,
  analyzeFromReports,
  buildDomainStats,
  categorizeFailure,
  DOMAIN_HEALTH_WINDOW_DAYS,
  groupProblemSources,
  isHealthyDmarcOutcome,
  isMailboxIpInfo,
  isMailboxNoiseAuthPattern,
  isScannerNoiseIpInfo,
  mergeDomainHealth,
  normalizeDispositionFilter,
  parseSourceIpFilter,
  reportsForDomainHealth,
  sendingSourceGroupsWithoutMailboxNoise
} from '../../shared/analyze'
import { diagnoseSource, type FailureDiagnosis } from '../../shared/diagnosis'
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
  type DomainHealth,
  type FailCategory,
  type ForensicReportRow,
  type NamedBucket,
  type NewSendingSourceGroup,
  type ProblemSourceRow,
  type ReportRow,
  type SendingServiceStatus,
  type SerializedRecord
} from '../../shared/types'
import { alertableSendingSources, parseDomainList } from '../../shared/sending-services'
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
  btnCloseDiagnosis,
  btnDiagnosisClose,
  btnExport,
  btnFilterReset,
  btnIpFilter,
  btnIpNoise,
  btnIpRdap,
  btnResetIgnoredProblemSources,
  detailEl,
  diagnosisBody,
  diagnosisDialog,
  ipContextMenu,
  ipContextNoiseBtn,
  ipContextSendingServiceBtn,
  dnsDomainEl,
  domainAmpelEl,
  tableProblemSources,
  filterChipsEl,
  filterDomainEl,
  filterFromEl,
  filterHideMailboxNoiseEl,
  filterPanelEl,
  filterRangeEl,
  simulationModeEl,
  filterToEl,
  filterCustomWrap,
  filterDispositionEl,
  forensicBody,
  ipDetailBody,
  ipDetailDialog,
  newSendingSourcesBannerEl,
  reportsBody,
  scannerNoiseHostsEl,
  tableFrom,
  tableIps,
  tableOrgs,
  sendingServiceAsnEl,
  sendingServiceCidrEl,
  sendingServiceDomainEl,
  sendingServiceNoteEl,
  sendingServiceProviderEl,
  sendingServiceStatusEl
} from './dom'
import { escapeHtml, formatIpCellHtml, formatIpMetaHtml, formatRange } from './format'
import { invalidateIpMapSize, renderIpMap, setIpMapFilterHandler } from './ip-map'
import {
  findSpfPrefixesForDomain,
  problemSourceIgnoreKey,
  readIgnoredProblemSourceKeys,
  writeIgnoredProblemSourceKeys
} from './problem-source-state'
import { clearDrill, state, type DrillFilters } from './state'
import { openSettings, setNextSendingServiceCreatedHandler, showSettingsTab } from './settings-ui'
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
import { readCollapsedWidgetIds, writeCollapsedWidgetIds } from './widget-state'

const NEW_SENDING_SOURCES_WIDGET_ID = 'newSendingSources'
const collapsedWidgetIds = readCollapsedWidgetIds(window.localStorage)

function isWidgetCollapsed(widgetId: string): boolean {
  return collapsedWidgetIds.has(widgetId)
}

function setWidgetCollapsed(widgetId: string, collapsed: boolean): void {
  if (collapsed) collapsedWidgetIds.add(widgetId)
  else collapsedWidgetIds.delete(widgetId)
  writeCollapsedWidgetIds(window.localStorage, collapsedWidgetIds)
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

function sendingDomainsForIp(ip: string): string[] {
  const domains = new Set<string>()
  for (const report of state.fullResult?.reports ?? []) {
    for (const record of report.records) {
      if (record.sourceIp === ip) domains.add(record.headerFrom || report.domain)
    }
  }
  return [...domains]
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
  const grouped = groupProblemSources(visibleRows, (ip) => state.ipLabelCache.get(ip)).slice(0, 40)
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
    simulationModeEl.value !== 'off' ||
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
  simulationModeEl.value = 'off'
  filterHideMailboxNoiseEl.checked = false
  rangeBeforeDayFilter = null
  clearDrill()
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
    forensicReports: result.forensicReports
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

/** Gather the raw (already delivered, non-passing) records for a problem-source IP group. */
function collectDiagnosisRecords(ips: string[]): {
  records: SerializedRecord[]
  policyDomain: string
} {
  const records: SerializedRecord[] = []
  const domainCounts = new Map<string, number>()
  for (const report of state.viewResult?.reports ?? []) {
    for (const rec of report.records) {
      if (!ips.includes(rec.sourceIp) || isHealthyDmarcOutcome(rec)) continue
      records.push(rec)
      domainCounts.set(report.domain, (domainCounts.get(report.domain) ?? 0) + rec.count)
    }
  }
  let policyDomain = ''
  let best = -1
  for (const [domain, count] of domainCounts) {
    if (count > best) {
      best = count
      policyDomain = domain
    }
  }
  return { records, policyDomain }
}

function mechanismLine(kind: 'spf' | 'dkim', facts: FailureDiagnosis['spf']): string {
  if (!facts.domain) return t(`diagnosis.${kind}.missing`)
  if (facts.raw == null) return t(`diagnosis.${kind}.unknown`, { domain: facts.domain })
  if (facts.raw === 'pass') {
    return t(facts.aligned ? `diagnosis.${kind}.passAligned` : `diagnosis.${kind}.passNotAligned`)
  }
  return t(`diagnosis.${kind}.fail`, { domain: facts.domain, result: facts.raw })
}

const DIAGNOSIS_VERDICT_BADGE: Record<FailureDiagnosis['verdict'], string> = {
  likelyLegit: 'badge',
  possiblyLegit: 'badge warn',
  suspicious: 'badge bad',
  forwarded: 'badge'
}

function renderDiagnosisBody(ips: string[]): void {
  const { records, policyDomain } = collectDiagnosisRecords(ips)
  if (!records.length || !policyDomain) {
    diagnosisBody.innerHTML = `<p class="muted">${escapeHtml(t('diagnosis.empty'))}</p>`
    return
  }
  const meta = state.ipLabelCache.get(ips[0])
  const sender = meta?.provider ? { name: meta.provider, kind: meta.senderKind } : null
  const prefixes = spfPrefixesForDomain(policyDomain)
  const isOwn = ips.some((ip) => isAuthorizedSender(ip, prefixes))
  const diag = diagnoseSource(records, policyDomain, sender, isOwn)
  if (!diag) {
    diagnosisBody.innerHTML = `<p class="muted">${escapeHtml(t('diagnosis.empty'))}</p>`
    return
  }

  const senderLine = diag.senderName
    ? t('diagnosis.senderDetected', { name: diag.senderName })
    : diag.senderKind
      ? t('diagnosis.senderKindDetected', { kind: t(`sender.kind.${diag.senderKind}`) })
      : t('diagnosis.senderNone')

  diagnosisBody.innerHTML = `
    <p class="diagnosis-title">
      <span class="${DIAGNOSIS_VERDICT_BADGE[diag.verdict]}">${escapeHtml(t(`diagnosis.verdict.${diag.verdict}`))}</span>
    </p>
    <p class="hint">${escapeHtml(t(`diagnosis.verdictHint.${diag.verdict}`))}</p>
    <fieldset class="settings-group">
      <legend>${escapeHtml(t('diagnosis.section.sender'))}</legend>
      <p>${escapeHtml(senderLine)}</p>
    </fieldset>
    <fieldset class="settings-group">
      <legend>${escapeHtml(t('diagnosis.section.auth'))}</legend>
      <p>${escapeHtml(mechanismLine('spf', diag.spf))}</p>
      <p>${escapeHtml(mechanismLine('dkim', diag.dkim))}</p>
    </fieldset>
    <fieldset class="settings-group">
      <legend>${escapeHtml(t('diagnosis.section.recommendation'))}</legend>
      <p><strong>${escapeHtml(t(`diagnosis.action.${diag.action}`, { domain: diag.domain }))}</strong></p>
    </fieldset>
    <p class="hint">${escapeHtml(t('diagnosis.sampleCount', { count: diag.sampleCount, domain: diag.domain }))}</p>
  `
}

export function openDiagnosis(ips: string[]): void {
  if (!ips.length) return
  renderDiagnosisBody(ips)
  diagnosisDialog.showModal()
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

/** Names a group by service, not by IP: "Microsoft 365 for example.de" is actionable. */
function describeNewSourceGroup(group: NewSendingSourceGroup): string {
  const provider = group.provider ?? t('newSources.unknownProvider')
  return group.domain
    ? t('newSources.itemWithDomain', { provider, domain: group.domain })
    : t('newSources.itemNoDomain', { provider })
}

/** A single IPv4/IPv6 address as its narrowest CIDR, for prefilling the inventory form. */
function singleIpCidr(ip: string): string {
  return ip.includes(':') ? `${ip}/128` : `${ip}/32`
}

/**
 * Opens Settings on the "Sende-Dienste" tab with domain/CIDR/ASN prefilled from the group,
 * leaving the service name blank — the user must confirm/name it explicitly before saving.
 */
function openSendingServiceFormFor(
  group: NewSendingSourceGroup,
  selectedIps?: string[],
  status: SendingServiceStatus = 'known'
): void {
  const ips = selectedIps ?? group.ips
  openSettings()
  showSettingsTab('sendingServices')
  setNextSendingServiceCreatedHandler(async (savedService) => {
    const selected = new Set(ips)
    const remainingIps = group.ips.filter((ip) => !selected.has(ip))
    if (savedService.status === 'known') {
      await window.api.acknowledgePendingSources(ips)
      group.ips = remainingIps
    } else if (remainingIps.length === 0) {
      group.provider = savedService.provider
      group.status = savedService.status
    } else {
      group.ips = remainingIps
      const groups = state.fullResult?.newSendingSources
      const groupIndex = groups?.indexOf(group) ?? -1
      if (groups && groupIndex >= 0) {
        groups.splice(groupIndex + 1, 0, {
          ...group,
          provider: savedService.provider,
          ips: [...ips],
          status: savedService.status
        })
      }
    }
    renderNewSendingSourcesBanner(state.fullResult)
  })
  sendingServiceProviderEl.value = ''
  sendingServiceDomainEl.value = group.domain ?? ''
  sendingServiceCidrEl.value = selectedIps
    ? ips.map(singleIpCidr).join(', ')
    : ips.length === 1
      ? singleIpCidr(ips[0]!)
      : ''
  sendingServiceAsnEl.value = selectedIps ? '' : group.asn != null ? String(group.asn) : ''
  sendingServiceStatusEl.value = status
  sendingServiceNoteEl.value =
    ips.length > 1 ? t('newSources.notePrefillIps', { ips: ips.join(', ') }) : ''
  sendingServiceProviderEl.focus()
}

function removeNewSourceItem(row: HTMLDivElement): void {
  row.remove()
  if (!newSendingSourcesBannerEl.querySelector('.new-source-item')) {
    renderNewSendingSourcesBanner(state.fullResult)
  }
}

function reviewIpsLabel(count: number): string {
  return t(count === 1 ? 'newSources.reviewIp' : 'newSources.reviewIps', { count })
}

function renderNewSourceItem(group: NewSendingSourceGroup): HTMLDivElement {
  const row = document.createElement('div')
  row.className = 'new-source-item'

  const label = document.createElement('div')
  label.className = 'new-source-label'
  const labelText = document.createElement('span')
  labelText.textContent = describeNewSourceGroup(group)
  label.appendChild(labelText)
  const statusBadge = document.createElement('span')
  statusBadge.className = 'badge new-source-status-badge hidden'
  label.appendChild(statusBadge)
  syncNewSourceStatusBadge(statusBadge, group.status)
  row.appendChild(label)

  const reviewBtn = document.createElement('button')
  reviewBtn.type = 'button'
  reviewBtn.className = 'btn secondary new-source-ips'
  reviewBtn.textContent = reviewIpsLabel(group.ips.length)
  row.appendChild(reviewBtn)

  const dialog = document.createElement('dialog')
  dialog.className = 'new-source-ip-dialog'
  const form = document.createElement('div')
  form.className = 'settings-form'

  const header = document.createElement('header')
  header.className = 'dialog-header'
  const title = document.createElement('h2')
  title.textContent = describeNewSourceGroup(group)
  header.appendChild(title)
  const closeBtn = document.createElement('button')
  closeBtn.type = 'button'
  closeBtn.className = 'btn ghost'
  closeBtn.textContent = '✕'
  closeBtn.setAttribute('aria-label', t('settings.close'))
  closeBtn.addEventListener('click', () => dialog.close())
  header.appendChild(closeBtn)
  form.appendChild(header)

  const body = document.createElement('div')
  body.className = 'dialog-body new-source-dialog-body'
  const hint = document.createElement('p')
  hint.className = 'hint new-source-dialog-hint'
  hint.textContent = t('newSources.dialogHint', { count: group.ips.length })
  body.appendChild(hint)

  const selectionBar = document.createElement('div')
  selectionBar.className = 'new-source-selection-bar'
  const selectAllLabel = document.createElement('label')
  selectAllLabel.className = 'checkbox'
  const selectAll = document.createElement('input')
  selectAll.type = 'checkbox'
  const selectAllText = document.createElement('span')
  selectAllText.textContent = t('newSources.selectAll')
  selectAllLabel.append(selectAll, selectAllText)
  selectionBar.appendChild(selectAllLabel)
  body.appendChild(selectionBar)

  const ipList = document.createElement('div')
  ipList.className = 'new-source-ip-list'
  body.appendChild(ipList)
  form.appendChild(body)

  const footer = document.createElement('footer')
  footer.className = 'dialog-footer'
  const selectedLabel = document.createElement('span')
  selectedLabel.className = 'hint'
  selectedLabel.textContent = t('newSources.selectedCount', { count: 0 })
  footer.appendChild(selectedLabel)
  const actions = document.createElement('div')
  actions.className = 'dialog-actions'
  const selectedStatus = createNewSourceStatusSelect()
  selectedStatus.classList.add('new-source-selected-status')
  actions.appendChild(selectedStatus)
  const cancelBtn = document.createElement('button')
  cancelBtn.type = 'button'
  cancelBtn.className = 'btn secondary'
  cancelBtn.textContent = t('settings.close')
  cancelBtn.addEventListener('click', () => dialog.close())
  actions.appendChild(cancelBtn)
  const createSelectedBtn = document.createElement('button')
  createSelectedBtn.type = 'button'
  createSelectedBtn.className = 'btn primary'
  createSelectedBtn.disabled = true
  createSelectedBtn.textContent = t('newSources.addSelectedService', { count: 0 })
  actions.appendChild(createSelectedBtn)
  footer.appendChild(actions)
  form.appendChild(footer)
  dialog.appendChild(form)
  row.appendChild(dialog)

  const ipCheckboxes: HTMLInputElement[] = []
  const syncSelection = (): void => {
    const activeCheckboxes = ipCheckboxes.filter((checkbox) => checkbox.isConnected)
    const selectedCount = activeCheckboxes.filter((checkbox) => checkbox.checked).length
    selectAll.checked = activeCheckboxes.length > 0 && selectedCount === activeCheckboxes.length
    selectAll.indeterminate = selectedCount > 0 && selectedCount < activeCheckboxes.length
    createSelectedBtn.disabled = selectedCount === 0
    createSelectedBtn.textContent = t('newSources.addSelectedService', { count: selectedCount })
    selectedLabel.textContent = t('newSources.selectedCount', { count: selectedCount })
  }

  const syncGroupCount = (): void => {
    reviewBtn.textContent = reviewIpsLabel(group.ips.length)
    hint.textContent = t('newSources.dialogHint', { count: group.ips.length })
    if (group.ips.length === 0) {
      dialog.close()
      removeNewSourceItem(row)
    }
  }

  for (const ip of group.ips) {
    const ipRow = document.createElement('div')
    ipRow.className = 'new-source-ip-row'

    const selectIp = document.createElement('input')
    selectIp.type = 'checkbox'
    selectIp.value = ip
    selectIp.setAttribute('aria-label', t('newSources.selectIp', { ip }))
    selectIp.addEventListener('change', syncSelection)
    ipCheckboxes.push(selectIp)
    ipRow.appendChild(selectIp)

    const address = document.createElement('span')
    address.className = 'mono'
    address.textContent = ip
    ipRow.appendChild(address)

    const metadata = document.createElement('div')
    metadata.className = 'new-source-ip-meta'
    metadata.dataset.sourceIpMeta = ip
    metadata.dataset.sourceDomain = group.domain ?? ''
    metadata.innerHTML = formatIpMetaHtml(ip, null, null, { sendingDomain: group.domain })

    const ipActions = document.createElement('div')
    ipActions.className = 'new-source-ip-actions'

    const filterBtn = document.createElement('button')
    filterBtn.type = 'button'
    filterBtn.className = 'btn secondary'
    filterBtn.textContent = t('ipDetail.filter')
    filterBtn.addEventListener('click', () => {
      dialog.close()
      setDrillFilter('sourceIp', ip)
    })
    ipActions.appendChild(filterBtn)

    const detailBtn = document.createElement('button')
    detailBtn.type = 'button'
    detailBtn.className = 'btn secondary'
    detailBtn.textContent = t('newSources.ipDetails')
    detailBtn.addEventListener('click', () => openIpDetail(ip))
    ipActions.appendChild(detailBtn)

    const noiseBtn = document.createElement('button')
    noiseBtn.type = 'button'
    noiseBtn.className = 'btn secondary'
    noiseBtn.textContent = t('newSources.markNoise')
    noiseBtn.addEventListener('click', () => {
      noiseBtn.disabled = true
      void addIpToScannerNoise(ip).then(async (added) => {
        if (!added) {
          noiseBtn.disabled = false
          return
        }
        try {
          await window.api.acknowledgePendingSources([ip])
          group.ips = group.ips.filter((candidate) => candidate !== ip)
          ipRow.remove()
          syncSelection()
          syncGroupCount()
        } catch (err) {
          noiseBtn.disabled = false
          setStatus(err instanceof Error ? err.message : String(err), 'error')
        }
      })
    })
    ipActions.appendChild(noiseBtn)

    const rejectBtn = document.createElement('button')
    rejectBtn.type = 'button'
    rejectBtn.className = 'btn danger'
    rejectBtn.textContent = t('newSources.noService')
    rejectBtn.addEventListener('click', () => {
      rejectBtn.disabled = true
      void window.api
        .acknowledgePendingSources([ip])
        .then(() => {
          group.ips = group.ips.filter((candidate) => candidate !== ip)
          ipRow.remove()
          syncSelection()
          syncGroupCount()
          setStatus(t('newSources.ipRemoved'), 'ok')
        })
        .catch((err: unknown) => {
          rejectBtn.disabled = false
          setStatus(err instanceof Error ? err.message : String(err), 'error')
        })
    })
    ipActions.appendChild(rejectBtn)

    ipRow.appendChild(ipActions)
    ipRow.appendChild(metadata)

    ipList.appendChild(ipRow)
  }
  selectAll.addEventListener('change', () => {
    for (const checkbox of ipCheckboxes.filter((item) => item.isConnected)) {
      checkbox.checked = selectAll.checked
    }
    syncSelection()
  })
  createSelectedBtn.addEventListener('click', () => {
    const selectedIps = ipCheckboxes
      .filter((checkbox) => checkbox.isConnected && checkbox.checked)
      .map((checkbox) => checkbox.value)
    if (selectedIps.length) {
      dialog.close()
      openSendingServiceFormFor(group, selectedIps, selectedStatus.value as SendingServiceStatus)
    }
  })
  reviewBtn.addEventListener('click', () => dialog.showModal())

  const mainActions = document.createElement('div')
  mainActions.className = 'new-source-main-actions'
  if (group.provider) {
    const statusAction = document.createElement('div')
    statusAction.className = 'new-source-main-action new-source-status-action'
    const statusSelect = createNewSourceStatusSelect(group.status)
    statusAction.appendChild(statusSelect)
    const applyStatusBtn = document.createElement('button')
    applyStatusBtn.type = 'button'
    applyStatusBtn.className = 'btn secondary'
    applyStatusBtn.textContent = t('newSources.applyStatus')
    const syncStatusAction = (): void => {
      const isSaved = group.status !== 'unknown' && statusSelect.value === group.status
      applyStatusBtn.disabled = isSaved
      applyStatusBtn.textContent = t(isSaved ? 'newSources.statusSaved' : 'newSources.applyStatus')
    }
    statusSelect.addEventListener('change', syncStatusAction)
    applyStatusBtn.addEventListener('click', () => {
      statusSelect.disabled = true
      applyStatusBtn.disabled = true
      void saveSendingSourceStatus(group, row, statusSelect, statusBadge, syncStatusAction)
    })
    syncStatusAction()
    statusAction.appendChild(applyStatusBtn)
    mainActions.appendChild(statusAction)
  } else {
    // No recognized service name to match on — offer a prefilled manual entry instead.
    const addBtn = document.createElement('button')
    addBtn.type = 'button'
    addBtn.className = 'btn secondary new-source-main-action new-source-service-action'
    addBtn.textContent = t('newSources.addService')
    addBtn.addEventListener('click', () => openSendingServiceFormFor(group))
    mainActions.appendChild(addBtn)
  }

  const groupNoiseBtn = document.createElement('button')
  groupNoiseBtn.type = 'button'
  groupNoiseBtn.className = 'btn secondary new-source-group-noise'
  groupNoiseBtn.textContent = t('newSources.markGroupNoise')
  groupNoiseBtn.addEventListener('click', () => {
    groupNoiseBtn.disabled = true
    const ips = [...group.ips]
    void addIpsToScannerNoise(ips).then(async (added) => {
      if (!added) {
        groupNoiseBtn.disabled = false
        return
      }
      try {
        await window.api.acknowledgePendingSources(ips)
        group.ips = []
        removeNewSourceItem(row)
      } catch (err) {
        groupNoiseBtn.disabled = false
        setStatus(err instanceof Error ? err.message : String(err), 'error')
      }
    })
  })
  mainActions.appendChild(groupNoiseBtn)
  row.appendChild(mainActions)

  const deleteBtn = document.createElement('button')
  deleteBtn.type = 'button'
  deleteBtn.className = 'btn danger new-source-delete'
  deleteBtn.textContent = t('newSources.deleteGroup')
  deleteBtn.addEventListener('click', () => {
    deleteBtn.disabled = true
    void window.api
      .acknowledgePendingSources(group.ips)
      .then(() => {
        group.ips = []
        removeNewSourceItem(row)
        setStatus(t('newSources.groupDeleted'), 'ok')
      })
      .catch((err: unknown) => {
        deleteBtn.disabled = false
        setStatus(err instanceof Error ? err.message : String(err), 'error')
      })
  })
  row.appendChild(deleteBtn)

  return row
}

function createNewSourceStatusSelect(initial: SendingServiceStatus = 'known'): HTMLSelectElement {
  const select = document.createElement('select')
  select.setAttribute('aria-label', t('sendingServices.statusLabel'))
  select.title = t('sendingServices.statusHint')
  for (const status of ['known', 'investigate', 'retired'] as const) {
    const option = document.createElement('option')
    option.value = status
    option.textContent = t(`sendingServices.status.${status}`)
    option.selected = status === initial
    select.appendChild(option)
  }
  return select
}

function syncNewSourceStatusBadge(badge: HTMLSpanElement, status: SendingServiceStatus): void {
  badge.classList.remove('hidden', 'warn', 'bad')
  if (status === 'investigate') {
    badge.classList.add('warn')
  } else if (status === 'retired') {
    badge.classList.add('bad')
  } else {
    badge.classList.add('hidden')
    return
  }
  badge.textContent = t(`sendingServices.status.${status}`)
}

function refreshNewSourceIpMetadata(): void {
  for (const metadata of newSendingSourcesBannerEl.querySelectorAll<HTMLElement>(
    '[data-source-ip-meta]'
  )) {
    metadata.innerHTML = formatIpMetaHtml(metadata.dataset.sourceIpMeta ?? '', null, null, {
      sendingDomain: metadata.dataset.sourceDomain || null
    })
  }
}

/** Reuses an existing plain provider+domain entry instead of creating a duplicate row. */
async function saveSendingSourceStatus(
  group: NewSendingSourceGroup,
  row: HTMLDivElement,
  select: HTMLSelectElement,
  statusBadge: HTMLSpanElement,
  syncStatusAction: () => void
): Promise<void> {
  try {
    const status = select.value as SendingServiceStatus
    const existing = await window.api.listSendingServices()
    const groupDomain = (group.domain ?? '').trim().toLowerCase()
    // Only reuse an exact single-domain (or exact wildcard) entry — never a multi-domain
    // list, since overwriting its `domain` here would silently drop the other domains.
    const match = existing.find((svc) => {
      if (svc.provider.toLowerCase() !== (group.provider ?? '').toLowerCase()) return false
      if (svc.cidr || svc.asn != null) return false
      const domains = parseDomainList(svc.domain)
      return groupDomain ? domains.length === 1 && domains[0] === groupDomain : domains.length === 0
    })
    await window.api.saveSendingService({
      id: match?.id,
      provider: group.provider!,
      domain: group.domain,
      cidr: null,
      asn: null,
      status,
      team: match?.team ?? null,
      note: match?.note ?? null
    })
    group.status = status
    if (status === 'known') {
      await window.api.acknowledgePendingSources(group.ips)
      setStatus(t('newSources.marked'), 'ok')
      group.ips = []
      removeNewSourceItem(row)
      return
    }
    select.disabled = false
    syncNewSourceStatusBadge(statusBadge, status)
    syncStatusAction()
    setStatus(
      t(status === 'investigate' ? 'newSources.investigateSaved' : 'newSources.retiredSaved'),
      status === 'investigate' ? 'ok' : 'error'
    )
  } catch (err) {
    select.disabled = false
    syncStatusAction()
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  }
}

/** Dashboard banner naming freshly seen (provider, domain) pairs not yet inventoried as known. */
function renderNewSendingSourcesBanner(result: AnalyzeResult | null): void {
  if (!result) {
    newSendingSourcesBannerEl.innerHTML = ''
    newSendingSourcesBannerEl.classList.add('hidden')
    return
  }
  const noiseFilteredGroups = sendingSourceGroupsWithoutMailboxNoise(
    result.newSendingSources ?? [],
    result.reports ?? [],
    collectScannerNoiseIps()
  )
  const groups = alertableSendingSources(noiseFilteredGroups)
  newSendingSourcesBannerEl.innerHTML = ''
  newSendingSourcesBannerEl.classList.remove('hidden')
  const collapsed = isWidgetCollapsed(NEW_SENDING_SOURCES_WIDGET_ID)

  const head = document.createElement('div')
  head.className = 'new-sources-banner-head widget-heading-clickable'
  const headingText = document.createElement('div')
  headingText.className = 'new-sources-heading-text widget-heading'
  const title = document.createElement('h2')
  title.textContent = t('newSources.title')
  title.setAttribute('aria-expanded', String(!collapsed))
  headingText.appendChild(title)
  const info = document.createElement('span')
  info.className = 'widget-info'
  const infoButton = document.createElement('button')
  infoButton.type = 'button'
  infoButton.className = 'widget-info-button'
  infoButton.setAttribute('aria-label', t('widget.info'))
  infoButton.setAttribute('aria-describedby', 'new-sources-info')
  infoButton.textContent = 'i'
  info.appendChild(infoButton)
  const infoPopover = document.createElement('span')
  infoPopover.id = 'new-sources-info'
  infoPopover.className = 'widget-info-popover'
  infoPopover.setAttribute('role', 'tooltip')
  infoPopover.textContent = t('newSources.info')
  info.appendChild(infoPopover)
  headingText.appendChild(info)
  const collapsedInfo = document.createElement('span')
  collapsedInfo.className = 'hint new-sources-collapsed-info'
  collapsedInfo.textContent = groups.length
    ? t('newSources.hiddenCount', { count: groups.length })
    : t('newSources.empty')
  collapsedInfo.classList.toggle('is-placeholder', !collapsed)
  collapsedInfo.setAttribute('aria-hidden', String(!collapsed))
  headingText.appendChild(collapsedInfo)
  head.appendChild(headingText)

  const toggleBtn = document.createElement('button')
  toggleBtn.type = 'button'
  toggleBtn.className = 'btn secondary widget-collapse-toggle'
  toggleBtn.dataset.widgetCollapseId = NEW_SENDING_SOURCES_WIDGET_ID
  updateWidgetToggle(toggleBtn, collapsed)
  const toggleWidget = (): void => {
    setWidgetCollapsed(NEW_SENDING_SOURCES_WIDGET_ID, !collapsed)
    renderNewSendingSourcesBanner(result)
  }
  toggleBtn.addEventListener('click', toggleWidget)
  head.addEventListener('click', (event) => {
    if (!isInteractiveWidgetHeadingTarget(event.target)) toggleWidget()
  })
  initWidgetTitleKeyboard(title, toggleWidget)
  head.appendChild(toggleBtn)
  newSendingSourcesBannerEl.appendChild(head)

  if (collapsed) return

  if (groups.length === 0) {
    const empty = document.createElement('p')
    empty.className = 'hint new-sources-empty'
    empty.textContent = t('newSources.empty')
    newSendingSourcesBannerEl.appendChild(empty)
    return
  }

  const hint = document.createElement('p')
  hint.className = 'hint'
  hint.textContent = t('newSources.hint')
  newSendingSourcesBannerEl.appendChild(hint)

  const list = document.createElement('div')
  list.className = 'new-sources-list'
  for (const group of groups) {
    list.appendChild(renderNewSourceItem(group))
  }
  newSendingSourcesBannerEl.appendChild(list)
}

export function applyView(): void {
  renderFilterChips()
  syncFilterResetButton()
  if (!state.fullResult) {
    state.viewResult = null
    state.spfExpandToken++
    state.spfPrefixes = []
    state.spfPrefixesByDomain.clear()
    updateSummary(null)
    renderDashboard(null)
    renderReports(null)
    renderForensic(null)
    renderNewSendingSourcesBanner(null)
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
  renderNewSendingSourcesBanner(result)
  void refreshSendingServicesForMetadata()
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

async function refreshSendingServicesForMetadata(): Promise<void> {
  try {
    state.sendingServices = await window.api.listSendingServices()
    if (!state.fullResult) return
    applyView()
    renderNewSendingSourcesBanner(state.fullResult)
    if (state.selectedReportId && state.viewResult) {
      const selected = state.viewResult.reports.find((r) => r.reportId === state.selectedReportId) ?? null
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
  initStickyFilter()
  initTables()
  initCollapsibleWidgets()
  setIpMapFilterHandler((ip) => setDrillFilter('sourceIp', ip))
  setVolumeDayClickHandler(filterVolumeByDay)

  btnCloseIpDetail.addEventListener('click', () => ipDetailDialog.close())
  btnCloseDiagnosis?.addEventListener('click', () => diagnosisDialog.close())
  btnDiagnosisClose?.addEventListener('click', () => diagnosisDialog.close())
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
    syncCustomRangeVisibility()
    applyView()
  })
  filterFromEl.addEventListener('change', () => applyView())
  filterToEl.addEventListener('change', () => applyView())
  filterDomainEl.addEventListener('change', () => {
    if (!filterDomainEl.value && simulationModeEl.value !== 'off') simulationModeEl.value = 'off'
    applyView()
  })
  filterDispositionEl.addEventListener('change', () => applyView())
  simulationModeEl.addEventListener('change', () => {
    ensureSimulationDomain()
    applyView()
  })
  filterHideMailboxNoiseEl.addEventListener('change', () => {
    applyView()
    void persistHideMailboxNoise()
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
  const domains = new Set<string>()
  for (const report of state.fullResult?.reports ?? []) {
    for (const rec of report.records) {
      if (rec.sourceIp !== ip) continue
      domains.add(rec.headerFrom || report.domain)
    }
  }
  return [...domains].filter(Boolean).sort()
}

/** Opens Settings on "Sende-Dienste" with everything prefilled from a known IP's context menu. */
function openSendingServiceFormForIp(ip: string): void {
  if (!ip) return
  const info = state.ipLabelCache.get(ip)
  openSettings()
  showSettingsTab('sendingServices')
  setNextSendingServiceCreatedHandler(async (savedService) => {
    if (savedService.status === 'known') {
      await window.api.acknowledgePendingSources([ip])
    }
  })
  sendingServiceProviderEl.value = info?.provider ?? ''
  sendingServiceDomainEl.value = domainsForIp(ip).join(', ')
  sendingServiceCidrEl.value = singleIpCidr(ip)
  sendingServiceAsnEl.value = info?.asn != null ? String(info.asn) : ''
  sendingServiceStatusEl.value = 'known'
  sendingServiceNoteEl.value = ''
  sendingServiceProviderEl.focus()
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
