import { buildDomainStats } from '../../shared/analyze'
import { normalizeDomain } from '../../shared/dmarc-builder'
import { t, type MessageKey } from '../../shared/i18n'
import {
  assessRollout,
  ROLLOUT_WINDOW_DAYS,
  type RolloutAssessment,
  type RolloutBlocker,
  type RolloutStep
} from '../../shared/rollout'
import type { DnsCheckResult } from '../../shared/types'
import {
  btnCloseRollout,
  btnRollout,
  btnRolloutRefresh,
  filterDomainEl,
  rolloutDialog,
  rolloutDomainEl,
  rolloutResultEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

const dnsByDomain = new Map<string, DnsCheckResult>()
let copyResetTimer: ReturnType<typeof setTimeout> | null = null
let lastAssessment: RolloutAssessment | null = null

function domainOptions(): string[] {
  const domains = state.fullResult?.aggregate.domains ?? []
  return [...new Set(domains.map((d) => normalizeDomain(d)).filter(Boolean))].sort()
}

function selectorsFor(domain: string): string[] {
  const reports = state.fullResult?.reports ?? []
  const stats = buildDomainStats(reports).find((s) => s.domain === domain)
  return stats?.dkimSelectors ?? []
}

function stageLabel(id: string): string {
  return t(`rollout.stage.${id}` as MessageKey)
}

function metricTile(labelKey: MessageKey, value: string, hintKey?: MessageKey): string {
  const title = hintKey ? ` title="${escapeHtml(t(hintKey))}"` : ''
  return `<div class="rollout-metric"${title}>
    <span class="rollout-metric-label">${escapeHtml(t(labelKey))}</span>
    <span class="rollout-metric-value">${escapeHtml(value)}</span>
  </div>`
}

function blockerText(blocker: RolloutBlocker): string {
  return t(`rollout.blocker.${blocker.key}` as MessageKey, {
    actual: blocker.actual ?? 0,
    limit: blocker.limit ?? 0
  })
}

function copyButton(value: string): string {
  return `<button type="button" class="btn secondary btn-copy" data-copy="${escapeHtml(value)}">${escapeHtml(t('rollout.copy'))}</button>`
}

function stepHtml(step: RolloutStep): string {
  const condition =
    step.minDays > 0
      ? t('rollout.stepCondition', { days: step.minDays, limit: step.maxRiskRate })
      : t('rollout.stepConditionStart')
  return `<li class="rollout-step ${step.state}">
    <div class="rollout-step-head">
      <span class="rollout-step-name">${escapeHtml(stageLabel(step.id))}</span>
      <span class="badge rollout-step-state">${escapeHtml(t(`rollout.state.${step.state}` as MessageKey))}</span>
    </div>
    <p class="hint">${escapeHtml(condition)}</p>
    <div class="rollout-step-record">
      <code class="mono">${escapeHtml(step.record)}</code>
      ${copyButton(step.record)}
    </div>
  </li>`
}

function verdictHtml(assessment: RolloutAssessment): string {
  const current = assessment.currentStage
    ? stageLabel(assessment.currentStage)
    : t('rollout.currentNone')
  let tone = 'blocked'
  let headline = ''
  let body = ''
  if (!assessment.nextStage) {
    tone = 'done'
    headline = t('rollout.verdict.done')
    body = t('rollout.verdict.doneBody')
  } else if (assessment.ready) {
    tone = 'ready'
    headline = t('rollout.verdict.ready', { stage: stageLabel(assessment.nextStage) })
    body = t('rollout.verdict.readyBody')
  } else {
    headline = t('rollout.verdict.blocked', { stage: stageLabel(assessment.nextStage) })
    body = t('rollout.verdict.blockedBody')
  }
  return `<section class="rollout-verdict ${tone}">
    <span class="rollout-verdict-current">${escapeHtml(t('rollout.current', { stage: current }))}</span>
    <h3>${escapeHtml(headline)}</h3>
    <p>${escapeHtml(body)}</p>
  </section>`
}

function render(assessment: RolloutAssessment): void {
  lastAssessment = assessment
  const m = assessment.metrics
  const blockers = assessment.blockers.length
    ? `<section class="rollout-section">
        <h4>${escapeHtml(t('rollout.blockers'))}</h4>
        <ul class="rollout-list">
          ${assessment.blockers.map((b) => `<li>${escapeHtml(blockerText(b))}</li>`).join('')}
        </ul>
      </section>`
    : ''
  const sources = assessment.riskSources.length
    ? `<section class="rollout-section">
        <h4>${escapeHtml(t('rollout.sources'))}</h4>
        <ul class="rollout-list rollout-sources">
          ${assessment.riskSources
            .map(
              (s) => `<li>
                <code class="mono">${escapeHtml(s.sourceIp)}</code>
                <span class="badge">${escapeHtml(t(`problems.cat.${s.category}` as MessageKey))}</span>
                <span class="muted">${escapeHtml(t('rollout.sourceMeta', { count: s.count, from: s.headerFrom ?? '—' }))}</span>
              </li>`
            )
            .join('')}
        </ul>
      </section>`
    : ''

  rolloutResultEl.innerHTML = `
    ${verdictHtml(assessment)}
    <div class="rollout-metrics">
      ${metricTile('rollout.metric.messages', String(m.messages))}
      ${metricTile('rollout.metric.healthRate', `${m.healthRate}%`)}
      ${metricTile('rollout.metric.riskRate', `${m.riskRate}%`, 'rollout.metricHint.riskRate')}
      ${metricTile('rollout.metric.spoof', String(m.spoof), 'rollout.metricHint.spoof')}
      ${metricTile('rollout.metric.days', String(m.daysObserved))}
      ${metricTile('rollout.metric.orgs', String(m.reportingOrgs))}
    </div>
    ${blockers}
    ${sources}
    <section class="rollout-section">
      <h4>${escapeHtml(t('rollout.plan'))}</h4>
      <ol class="rollout-plan">${assessment.plan.map(stepHtml).join('')}</ol>
    </section>`
}

function setMessage(text: string, tone: 'muted' | 'error' = 'muted'): void {
  lastAssessment = null
  rolloutResultEl.innerHTML = `<p class="${tone}">${escapeHtml(text)}</p>`
}

async function evaluate(domain: string, forceDns = false): Promise<void> {
  const reports = state.fullResult?.reports ?? []
  if (!domain) {
    setMessage(t('rollout.empty'))
    return
  }
  let dns = dnsByDomain.get(domain) ?? null
  if (!dns || forceDns) {
    setMessage(t('rollout.loading', { domain }))
    try {
      dns = await window.api.checkDns(domain, selectorsFor(domain))
      dnsByDomain.set(domain, dns)
    } catch (err) {
      setMessage(
        t('rollout.error', { message: err instanceof Error ? err.message : String(err) }),
        'error'
      )
      return
    }
    // A slow DNS answer must not overwrite a domain the user switched to meanwhile.
    if (normalizeDomain(rolloutDomainEl.value) !== domain) return
  }
  render(assessRollout({ domain, reports, dns, windowDays: ROLLOUT_WINDOW_DAYS }))
}

function fillDomains(): string {
  const domains = domainOptions()
  const preferred = normalizeDomain(filterDomainEl.value || '') || domains[0] || ''
  rolloutDomainEl.innerHTML = domains
    .map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`)
    .join('')
  const selected = domains.includes(preferred) ? preferred : (domains[0] ?? '')
  if (selected) rolloutDomainEl.value = selected
  rolloutDomainEl.disabled = domains.length === 0
  return selected
}

/** Pre-fill the DNS answer for a domain (screenshot capture runs without network). */
export function seedRolloutDns(domain: string, dns: DnsCheckResult): void {
  dnsByDomain.set(normalizeDomain(domain), dns)
}

export function openRollout(): void {
  const domain = fillDomains()
  rolloutDialog.showModal()
  void evaluate(domain)
}

export function refreshRolloutLocale(): void {
  if (!rolloutDialog.open) return
  if (lastAssessment) render(lastAssessment)
  else void evaluate(normalizeDomain(rolloutDomainEl.value))
}

export function initRolloutUi(): void {
  btnRollout.addEventListener('click', () => openRollout())
  btnCloseRollout.addEventListener('click', () => rolloutDialog.close())
  rolloutDomainEl.addEventListener('change', () => {
    void evaluate(normalizeDomain(rolloutDomainEl.value))
  })
  btnRolloutRefresh.addEventListener('click', () => {
    void evaluate(normalizeDomain(rolloutDomainEl.value), true)
  })
  rolloutResultEl.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null
    const btn = target?.closest?.('.btn-copy') as HTMLButtonElement | null
    if (!btn) return
    void navigator.clipboard.writeText(btn.getAttribute('data-copy') ?? '').then(() => {
      btn.textContent = t('rollout.copied')
      if (copyResetTimer) clearTimeout(copyResetTimer)
      copyResetTimer = setTimeout(() => {
        btn.textContent = t('rollout.copy')
      }, 1500)
    })
  })
}
