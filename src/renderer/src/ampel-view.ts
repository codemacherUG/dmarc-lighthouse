import {
  buildDomainStats,
  DOMAIN_HEALTH_WINDOW_DAYS,
  mergeDomainHealth,
  reportsForDomainHealth
} from '../../shared/analyze'
import { t, type MessageKey } from '../../shared/i18n'
import type { AnalyzeResult, DomainHealth, ReportRow } from '../../shared/types'
import { domainAmpelEl, filterDomainEl, simulationModeEl } from './dom'
import { openDnsHistory, openDomainDkimSettings } from './domain-settings-modal'
import { escapeHtml } from './format'
import { state } from './state'

let onAmpelDomainChanged: (() => void) | null = null

export function setAmpelDomainChangedCallback(cb: () => void): void {
  onAmpelDomainChanged = cb
}

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

export function renderDomainAmpel(rows: DomainHealth[]): void {
  if (!rows.length) {
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.empty'))}</p>`
    return
  }
  const selectedDomain = filterDomainEl?.value.trim().toLowerCase() ?? ''
  domainAmpelEl.innerHTML = rows
    .map((h) => {
      const statusLabel = t(`health.status.${h.status}` as MessageKey)
      const policy =
        h.dmarcPolicy != null ? escapeHtml(t('health.policy', { policy: h.dmarcPolicy })) : '—'
      const reasons = h.reasons.map((key) => t(key as MessageKey)).join(' · ')
      const isSelected = Boolean(selectedDomain) && h.domain.trim().toLowerCase() === selectedDomain
      return `
      <div class="ampel-card-wrap${isSelected ? ' is-selected' : ''}">
        <button type="button" class="ampel-card ${h.status}${isSelected ? ' is-selected' : ''}" data-domain="${escapeHtml(h.domain)}" aria-pressed="${isSelected ? 'true' : 'false'}" title="${escapeHtml(statusLabel)}">
          <div class="ampel-domain">${escapeHtml(h.domain)}</div>
          <div class="ampel-meta">
            <span>${escapeHtml(statusLabel)}</span>
            <span>${escapeHtml(t('health.passRate', { rate: h.passRate.toFixed(1) }))}</span>
            <span>${escapeHtml(t('health.msgs', { count: String(h.total) }))}</span>
            <span>${escapeHtml(t('health.window', { days: String(DOMAIN_HEALTH_WINDOW_DAYS) }))}</span>
            <span>${policy}</span>
          </div>
          ${reasons ? `<div class="ampel-reasons">${escapeHtml(reasons)}</div>` : ''}
        </button>
        <button type="button" class="ampel-info" data-domain="${escapeHtml(h.domain)}" aria-label="${escapeHtml(t('health.dnsHistory', { domain: h.domain }))}" title="${escapeHtml(t('health.dnsHistory', { domain: h.domain }))}">i</button>
        <button type="button" class="ampel-settings" data-domain="${escapeHtml(h.domain)}" aria-label="${escapeHtml(t('health.dkimManage', { domain: h.domain }))}" title="${escapeHtml(t('health.dkimManage', { domain: h.domain }))}">⚙</button>
      </div>`
    })
    .join('')

  for (const btn of domainAmpelEl.querySelectorAll<HTMLButtonElement>('.ampel-card[data-domain]')) {
    btn.addEventListener('click', () => {
      const domain = btn.dataset.domain ?? ''
      if (!domain) return
      if (filterDomainEl.value.trim().toLowerCase() === domain.trim().toLowerCase()) {
        filterDomainEl.value = ''
        if (simulationModeEl.value !== 'off') simulationModeEl.value = 'off'
      } else {
        selectDomainFilter(domain)
      }
      onAmpelDomainChanged?.()
    })
  }
  for (const btn of domainAmpelEl.querySelectorAll<HTMLButtonElement>('.ampel-info[data-domain]')) {
    btn.addEventListener('click', () => {
      const domain = btn.dataset.domain ?? ''
      if (domain) void openDnsHistory(domain)
    })
  }
  for (const btn of domainAmpelEl.querySelectorAll<HTMLButtonElement>(
    '.ampel-settings[data-domain]'
  )) {
    btn.addEventListener('click', () => {
      const domain = btn.dataset.domain ?? ''
      if (domain) void openDomainDkimSettings(domain)
    })
  }
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
