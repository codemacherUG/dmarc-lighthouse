import {
  buildDomainStats,
  DOMAIN_HEALTH_WINDOW_DAYS,
  mergeDomainHealth,
  reportsForDomainHealth
} from '../../shared/analyze'
import { t, type MessageKey } from '../../shared/i18n'
import type { AnalyzeResult, DomainHealth, ReportRow } from '../../shared/types'
import {
  ampelQuickActionsForReasons,
  filterAndSortDomainHealth,
  readDashboardUiState,
  writeDashboardUiState,
  type AmpelSortOrder,
  type AmpelStatusFilter
} from './dashboard-ui-state'
import {
  ampelCompactToggleEl,
  ampelSearchEl,
  ampelSortEl,
  domainAmpelEl,
  domainAmpelToolbarEl,
  filterDomainEl,
  simulationModeEl
} from './dom'
import { openDnsHistory, openDomainDkimSettings } from './domain-settings-modal'
import { escapeHtml } from './format'
import { state } from './state'
import {
  domainToolActionButtonHtml,
  triggerDomainToolAction,
  type DomainToolAction
} from './wizard-common'

export { ampelQuickActionsForReasons, filterAndSortDomainHealth }

let onAmpelDomainChanged: (() => void) | null = null

export function setAmpelDomainChangedCallback(cb: () => void): void {
  onAmpelDomainChanged = cb
}

const initialUi = readDashboardUiState(typeof window !== 'undefined' ? window.localStorage : null)
let currentStatusFilter: AmpelStatusFilter = 'all'
let currentSearchQuery = ''
let currentSort: AmpelSortOrder = initialUi.ampelSort
let isCompact: boolean = initialUi.ampelCompact
let lastSourceRows: DomainHealth[] = []
let toolbarBound = false
let ampelDelegationBound = false

/** Select a domain option case-insensitively (Ampel domains are lowercased). */
export function selectDomainFilter(domain: string): void {
  const wanted = domain.trim().toLowerCase()
  const match = [...filterDomainEl.options].find((o) => o.value.toLowerCase() === wanted)
  if (!match && domain.trim()) {
    const opt = document.createElement('option')
    opt.value = domain.trim()
    opt.textContent = domain.trim()
    filterDomainEl.appendChild(opt)
    filterDomainEl.value = opt.value
    return
  }
  filterDomainEl.value = match?.value ?? domain
}

export function syncDomainAmpelSelection(): void {
  if (!domainAmpelEl) return
  const selectedDomain = filterDomainEl?.value.trim().toLowerCase() ?? ''
  for (const btn of domainAmpelEl.querySelectorAll<HTMLButtonElement>('.ampel-card[data-domain]')) {
    const domain = (btn.dataset.domain ?? '').trim().toLowerCase()
    const isSelected = Boolean(selectedDomain) && domain === selectedDomain
    btn.classList.toggle('is-selected', isSelected)
    btn.setAttribute('aria-pressed', String(isSelected))
    btn.closest('.ampel-card-wrap')?.classList.toggle('is-selected', isSelected)
  }
}

function syncAmpelToolbar(rows: readonly DomainHealth[]): void {
  if (domainAmpelEl) {
    domainAmpelEl.classList.toggle('is-compact', isCompact)
  }
  if (!domainAmpelToolbarEl) return

  const showToolbar =
    rows.length > 1 || currentStatusFilter !== 'all' || Boolean(currentSearchQuery.trim())
  domainAmpelToolbarEl.classList.toggle('hidden', !showToolbar)

  const counts: Record<AmpelStatusFilter, number> = {
    all: rows.length,
    bad: 0,
    warn: 0,
    ok: 0
  }
  for (const r of rows) {
    if (r.status === 'bad') counts.bad += 1
    else if (r.status === 'warn') counts.warn += 1
    else if (r.status === 'ok') counts.ok += 1
  }

  for (const pill of domainAmpelToolbarEl.querySelectorAll<HTMLButtonElement>(
    '[data-ampel-status]'
  )) {
    const status = pill.dataset.ampelStatus as AmpelStatusFilter | undefined
    if (!status) continue
    const active = status === currentStatusFilter
    pill.classList.toggle('is-active', active)
    pill.setAttribute('aria-pressed', String(active))
    const badge = pill.querySelector<HTMLElement>('[data-ampel-count]')
    if (badge) badge.textContent = String(counts[status] ?? 0)
  }

  if (ampelSortEl && ampelSortEl.value !== currentSort) {
    ampelSortEl.value = currentSort
  }
  if (ampelCompactToggleEl) {
    ampelCompactToggleEl.classList.toggle('is-active', isCompact)
    ampelCompactToggleEl.setAttribute('aria-pressed', String(isCompact))
  }
}

function ensureAmpelBindings(): void {
  if (domainAmpelToolbarEl && !toolbarBound) {
    toolbarBound = true
    domainAmpelToolbarEl.addEventListener('click', (event) => {
      const target = event.target instanceof Element ? event.target : null
      const pill = target?.closest<HTMLButtonElement>('[data-ampel-status]')
      if (!pill) return
      const next = (pill.dataset.ampelStatus as AmpelStatusFilter | undefined) ?? 'all'
      currentStatusFilter = currentStatusFilter === next && next !== 'all' ? 'all' : next
      renderDomainAmpel(lastSourceRows)
    })
    ampelSearchEl?.addEventListener('input', () => {
      currentSearchQuery = ampelSearchEl?.value ?? ''
      renderDomainAmpel(lastSourceRows)
    })
    ampelSearchEl?.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && ampelSearchEl?.value) {
        event.preventDefault()
        event.stopPropagation()
        ampelSearchEl.value = ''
        currentSearchQuery = ''
        renderDomainAmpel(lastSourceRows)
      }
    })
    ampelSortEl?.addEventListener('change', () => {
      currentSort = (ampelSortEl?.value as AmpelSortOrder) || 'status'
      writeDashboardUiState(window.localStorage, { ampelSort: currentSort })
      renderDomainAmpel(lastSourceRows)
    })
    ampelCompactToggleEl?.addEventListener('click', () => {
      isCompact = !isCompact
      writeDashboardUiState(window.localStorage, { ampelCompact: isCompact })
      syncAmpelToolbar(lastSourceRows)
    })
  }

  if (domainAmpelEl && !ampelDelegationBound) {
    ampelDelegationBound = true
    domainAmpelEl.addEventListener('click', (event) => {
      const target = event.target instanceof Element ? event.target : null
      if (!target) return

      const toolBtn = target.closest<HTMLButtonElement>('[data-domain-tool]')
      if (toolBtn) {
        event.preventDefault()
        event.stopPropagation()
        const action = toolBtn.dataset.domainTool as DomainToolAction | undefined
        const domain = toolBtn.dataset.domain?.trim() ?? ''
        if (action && domain) triggerDomainToolAction(action, domain)
        return
      }

      const infoBtn = target.closest<HTMLButtonElement>('.ampel-info[data-domain]')
      if (infoBtn) {
        const domain = infoBtn.dataset.domain ?? ''
        if (domain) void openDnsHistory(domain)
        return
      }

      const settingsBtn = target.closest<HTMLButtonElement>('.ampel-settings[data-domain]')
      if (settingsBtn) {
        const domain = settingsBtn.dataset.domain ?? ''
        if (domain) void openDomainDkimSettings(domain)
        return
      }

      const cardBtn = target.closest<HTMLButtonElement>('.ampel-card[data-domain]')
      if (cardBtn) {
        const domain = cardBtn.dataset.domain ?? ''
        if (!domain) return
        if (filterDomainEl.value.trim().toLowerCase() === domain.trim().toLowerCase()) {
          filterDomainEl.value = ''
          if (simulationModeEl.value !== 'off') simulationModeEl.value = 'off'
        } else {
          selectDomainFilter(domain)
        }
        onAmpelDomainChanged?.()
      }
    })
  }
}

export function renderDomainAmpel(rows: DomainHealth[]): void {
  ensureAmpelBindings()
  lastSourceRows = rows
  syncAmpelToolbar(rows)

  if (!rows.length) {
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.empty'))}</p>`
    return
  }

  const visibleRows = filterAndSortDomainHealth(rows, {
    statusFilter: currentStatusFilter,
    query: currentSearchQuery,
    sort: currentSort
  })

  if (!visibleRows.length) {
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.noMatch'))}</p>`
    return
  }

  const selectedDomain = filterDomainEl?.value.trim().toLowerCase() ?? ''
  domainAmpelEl.innerHTML = visibleRows
    .map((h) => {
      const statusLabel = t(`health.status.${h.status}` as MessageKey)
      const policy =
        h.dmarcPolicy != null ? escapeHtml(t('health.policy', { policy: h.dmarcPolicy })) : '—'
      const reasons = h.reasons.map((key) => t(key as MessageKey)).join(' · ')
      const isSelected = Boolean(selectedDomain) && h.domain.trim().toLowerCase() === selectedDomain
      const quickActions = ampelQuickActionsForReasons(h.reasons)
      const actionsHtml = quickActions.length
        ? `<div class="ampel-card-actions">${quickActions
            .map((a) =>
              domainToolActionButtonHtml(a.action, h.domain, a.labelKey, 'ampel-action-chip')
            )
            .join('')}</div>`
        : ''
      return `
      <div class="ampel-card-wrap${isSelected ? ' is-selected' : ''}${quickActions.length ? ' has-actions' : ''}">
        <button type="button" class="ampel-card ${h.status}${isSelected ? ' is-selected' : ''}" data-domain="${escapeHtml(h.domain)}" aria-pressed="${isSelected ? 'true' : 'false'}" title="${escapeHtml(reasons ? `${statusLabel} — ${reasons}` : statusLabel)}">
          <div class="ampel-domain">${escapeHtml(h.domain)}</div>
          <div class="ampel-meta">
            <span>${escapeHtml(statusLabel)}</span>
            <span>${escapeHtml(t('health.passRate', { rate: h.passRate.toFixed(1) }))}</span>
            <span>${escapeHtml(t('health.msgs', { count: String(h.total) }))}</span>
            <span class="ampel-meta-window">${escapeHtml(t('health.window', { days: String(DOMAIN_HEALTH_WINDOW_DAYS) }))}</span>
            <span>${policy}</span>
          </div>
          ${reasons ? `<div class="ampel-reasons">${escapeHtml(reasons)}</div>` : ''}
        </button>
        ${actionsHtml}
        <button type="button" class="ampel-info" data-domain="${escapeHtml(h.domain)}" aria-label="${escapeHtml(t('health.dnsHistory', { domain: h.domain }))}" title="${escapeHtml(t('health.dnsHistory', { domain: h.domain }))}">i</button>
        <button type="button" class="ampel-settings" data-domain="${escapeHtml(h.domain)}" aria-label="${escapeHtml(t('health.dkimManage', { domain: h.domain }))}" title="${escapeHtml(t('health.dkimManage', { domain: h.domain }))}">⚙</button>
      </div>`
    })
    .join('')
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
export async function refreshDomainHealth(
  full: AnalyzeResult | null = state.fullResult,
  options: { force?: boolean } = {}
): Promise<void> {
  if (!domainAmpelEl) return
  if (!options.force && full && full === domainHealthSource) return
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
    syncAmpelToolbar([])
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
      health = await window.api.healthBatch(buildDomainStats(windowed))
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
