import { sendingSourceGroupsWithoutMailboxNoise } from '../../shared/analyze'
import {
  assessSourceRecords,
  summarizeSourceAuthOutcomes,
  type SourceAuthOutcomeSummary,
  type SourceIpAssessment
} from '../../shared/diagnosis'
import { t } from '../../shared/i18n'
import type { MailboxNoiseProvider } from '../../shared/mailbox-ip'
import { alertableSendingSources, parseDomainList } from '../../shared/sending-services'
import type {
  AnalyzeResult,
  NewSendingSourceGroup,
  ReportRow,
  SendingServiceStatus,
  SerializedRecord
} from '../../shared/types'
import { setStatus } from './chrome'
import { newSendingSourcesBannerEl } from './dom'
import { openDomainDkimSettings } from './domain-settings-modal'
import { formatIpMetaHtml } from './format'
import { state, type DrillFilters } from './state'

const NEW_SENDING_SOURCES_WIDGET_ID = 'newSendingSources'

export interface NewSourcesViewDeps {
  domainsForIp: (ip: string) => string[]
  setDrillFilter: (key: keyof DrillFilters, value: string) => void
  openIpDetail: (ip: string) => void
  addIpToScannerNoise: (ip: string) => Promise<boolean>
  addIpsToScannerNoise: (ips: readonly string[]) => Promise<boolean>
  collectScannerNoiseIps: () => Set<string>
  collectMailboxIps: () => Set<string>
  enabledMailboxNoiseProviders: () => ReadonlySet<MailboxNoiseProvider>
  isWidgetCollapsed: (widgetId: string) => boolean
  setWidgetCollapsed: (widgetId: string, collapsed: boolean) => void
  updateWidgetToggle: (button: HTMLButtonElement, collapsed: boolean) => void
  isInteractiveWidgetHeadingTarget: (target: EventTarget | null) => boolean
  initWidgetTitleKeyboard: (title: HTMLHeadingElement, toggleWidget: () => void) => void
}

let deps: NewSourcesViewDeps | null = null

export function configureNewSourcesView(nextDeps: NewSourcesViewDeps): void {
  deps = nextDeps
}

/** Names newly observed source IPs by detected network and From domain. */
function describeNewSourceGroup(group: NewSendingSourceGroup): string {
  const provider = group.provider ?? t('newSources.unknownProvider')
  return group.domain
    ? t('newSources.itemWithDomain', { provider, domain: group.domain })
    : t('newSources.itemNoDomain', { provider })
}

/** Opens the domain editor with a sender-service draft from a newly observed source. */
function openSendingServiceFormFor(
  group: NewSendingSourceGroup,
  selectedIps?: string[],
  status: SendingServiceStatus = 'known'
): void {
  const ips = selectedIps ?? group.ips
  const domain = group.domain || deps?.domainsForIp(ips[0] ?? '')[0]
  if (!domain) {
    setStatus(t('health.sendingServiceDomainRequired'))
    return
  }
  void openDomainDkimSettings(domain, {
    senderDraft: {
      provider: group.provider ?? '',
      status,
      note: t('newSources.notePrefillIps', { ips: ips.join(', ') })
    },
    onSenderSaved: async (savedService) => {
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
    }
  })
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

function summarizeNewSourceIp(
  ip: string,
  reports: ReportRow[],
  domain: string | null
): {
  passing: number
  failing: number
  rejected: number
  notRejected: number
  unknown: number
  assessment: SourceIpAssessment
  authOutcomes: SourceAuthOutcomeSummary[]
} | null {
  let passing = 0
  let failing = 0
  let rejected = 0
  let notRejected = 0
  let unknown = 0
  let found = false
  const sourceRecords: SerializedRecord[] = []
  const normalizedDomain = domain?.trim().toLowerCase()

  for (const report of reports) {
    for (const record of report.records) {
      if (record.sourceIp !== ip) continue
      if (
        normalizedDomain &&
        (record.headerFrom ?? report.domain).trim().toLowerCase() !== normalizedDomain
      ) {
        continue
      }
      found = true
      sourceRecords.push(record)
      const count = record.count || 0
      if (record.passesDmarc) passing += count
      else failing += count

      if (record.disposition == null || record.disposition === '') unknown += count
      else if (record.disposition.toLowerCase() === 'reject') rejected += count
      else notRejected += count
    }
  }

  const assessment = assessSourceRecords(sourceRecords)
  const authOutcomes = summarizeSourceAuthOutcomes(sourceRecords)
  return found && assessment
    ? { passing, failing, rejected, notRejected, unknown, assessment, authOutcomes }
    : null
}

function renderNewSourceItem(group: NewSendingSourceGroup, reports: ReportRow[]): HTMLDivElement {
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

    const ipStats = document.createElement('div')
    ipStats.className = 'new-source-ip-stats'
    const summary = summarizeNewSourceIp(ip, reports, group.domain)
    if (summary) {
      const dmarcGroup = document.createElement('div')
      dmarcGroup.className = 'new-source-ip-stat-group'
      const dmarcLabel = document.createElement('span')
      dmarcLabel.className = 'new-source-ip-stat-label'
      dmarcLabel.textContent = t('newSources.dmarcLabel')
      dmarcGroup.appendChild(dmarcLabel)
      const dmarcValues = document.createElement('div')
      dmarcValues.className = 'new-source-ip-stat-values'
      const passed = document.createElement('span')
      passed.className = 'new-source-ip-stat-value pass'
      passed.textContent = t('newSources.passedCount', { count: summary.passing })
      dmarcValues.appendChild(passed)
      const failed = document.createElement('span')
      failed.className = 'new-source-ip-stat-value fail'
      failed.textContent = t('newSources.failedCount', { count: summary.failing })
      dmarcValues.appendChild(failed)
      dmarcGroup.appendChild(dmarcValues)
      ipStats.appendChild(dmarcGroup)

      const dispositionGroup = document.createElement('div')
      dispositionGroup.className = 'new-source-ip-stat-group'
      const dispositionLabel = document.createElement('span')
      dispositionLabel.className = 'new-source-ip-stat-label'
      dispositionLabel.textContent = t('newSources.dispositionLabel')
      dispositionGroup.appendChild(dispositionLabel)
      const dispositionValues = document.createElement('div')
      dispositionValues.className = 'new-source-ip-stat-values'
      const rejected = document.createElement('span')
      rejected.className = 'new-source-ip-stat-value fail'
      rejected.textContent = t('newSources.rejectedCount', { count: summary.rejected })
      dispositionValues.appendChild(rejected)
      const notRejected = document.createElement('span')
      notRejected.className = 'new-source-ip-stat-value'
      notRejected.textContent = t('newSources.notRejectedCount', { count: summary.notRejected })
      dispositionValues.appendChild(notRejected)
      if (summary.unknown > 0) {
        const unknown = document.createElement('span')
        unknown.className = 'new-source-ip-stat-value warn'
        unknown.textContent = t('newSources.unknownDispositionCount', { count: summary.unknown })
        dispositionValues.appendChild(unknown)
      }
      dispositionGroup.appendChild(dispositionValues)
      ipStats.appendChild(dispositionGroup)

      if (summary.authOutcomes.length > 0) {
        const authGroup = document.createElement('div')
        authGroup.className = 'new-source-ip-stat-group'
        const authLabel = document.createElement('span')
        authLabel.className = 'new-source-ip-stat-label'
        authLabel.textContent = t('newSources.authOutcomeLabel')
        authGroup.appendChild(authLabel)
        const authValues = document.createElement('div')
        authValues.className = 'new-source-ip-stat-values'
        for (const outcome of summary.authOutcomes) {
          const authValue = document.createElement('span')
          authValue.className = 'new-source-ip-stat-value'
          authValue.textContent = t('newSources.authOutcome', {
            spf: outcome.spf ?? t('newSources.authUnknown'),
            dkim: outcome.dkim ?? t('newSources.authUnknown'),
            count: outcome.count
          })
          authValues.appendChild(authValue)
        }
        authGroup.appendChild(authValues)
        ipStats.appendChild(authGroup)
      }

      const assessmentGroup = document.createElement('div')
      assessmentGroup.className = 'new-source-ip-stat-group'
      const assessmentLabel = document.createElement('span')
      assessmentLabel.className = 'new-source-ip-stat-label'
      assessmentLabel.textContent = t('newSources.assessmentLabel')
      assessmentGroup.appendChild(assessmentLabel)
      const assessmentText = document.createElement('span')
      assessmentText.className = 'new-source-assessment-text'
      assessmentText.textContent = t(`newSources.assessment.${summary.assessment}`)
      assessmentGroup.appendChild(assessmentText)
      ipStats.appendChild(assessmentGroup)
    } else {
      ipStats.textContent = t('newSources.ipStatsUnavailable')
    }

    const ipActions = document.createElement('div')
    ipActions.className = 'new-source-ip-actions'

    const filterBtn = document.createElement('button')
    filterBtn.type = 'button'
    filterBtn.className = 'btn secondary'
    filterBtn.textContent = t('ipDetail.filter')
    filterBtn.addEventListener('click', () => {
      dialog.close()
      deps?.setDrillFilter('sourceIp', ip)
    })
    ipActions.appendChild(filterBtn)

    const detailBtn = document.createElement('button')
    detailBtn.type = 'button'
    detailBtn.className = 'btn secondary'
    detailBtn.textContent = t('newSources.ipDetails')
    detailBtn.addEventListener('click', () => deps?.openIpDetail(ip))
    ipActions.appendChild(detailBtn)

    const noiseBtn = document.createElement('button')
    noiseBtn.type = 'button'
    noiseBtn.className = 'btn secondary'
    noiseBtn.textContent = t('newSources.markNoise')
    noiseBtn.addEventListener('click', () => {
      if (!deps) return
      noiseBtn.disabled = true
      void deps.addIpToScannerNoise(ip).then(async (added) => {
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
    rejectBtn.className = 'btn secondary'
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
    ipRow.appendChild(ipStats)

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
    if (!deps) return
    groupNoiseBtn.disabled = true
    const ips = [...group.ips]
    void deps.addIpsToScannerNoise(ips).then(async (added) => {
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
  deleteBtn.className = 'btn secondary new-source-delete'
  deleteBtn.textContent = t('newSources.deleteGroup')
  deleteBtn.title = t('newSources.deleteGroup')
  deleteBtn.setAttribute('aria-label', t('newSources.deleteGroup'))
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

export function refreshNewSourceIpMetadata(): void {
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
export function renderNewSendingSourcesBanner(result: AnalyzeResult | null): void {
  if (!result || !deps) {
    newSendingSourcesBannerEl.innerHTML = ''
    newSendingSourcesBannerEl.classList.add('hidden')
    return
  }
  const noiseFilteredGroups = sendingSourceGroupsWithoutMailboxNoise(
    result.newSendingSources ?? [],
    result.reports ?? [],
    deps.collectScannerNoiseIps(),
    deps.collectMailboxIps(),
    deps.enabledMailboxNoiseProviders()
  )
  const groups = alertableSendingSources(noiseFilteredGroups)
  newSendingSourcesBannerEl.innerHTML = ''
  newSendingSourcesBannerEl.classList.remove('hidden')
  const collapsed = deps.isWidgetCollapsed(NEW_SENDING_SOURCES_WIDGET_ID)

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
  deps.updateWidgetToggle(toggleBtn, collapsed)
  const toggleWidget = (): void => {
    deps?.setWidgetCollapsed(NEW_SENDING_SOURCES_WIDGET_ID, !collapsed)
    renderNewSendingSourcesBanner(result)
  }
  toggleBtn.addEventListener('click', toggleWidget)
  head.addEventListener('click', (event) => {
    if (!deps?.isInteractiveWidgetHeadingTarget(event.target)) toggleWidget()
  })
  deps.initWidgetTitleKeyboard(title, toggleWidget)
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
    list.appendChild(renderNewSourceItem(group, result.reports))
  }
  newSendingSourcesBannerEl.appendChild(list)
}
