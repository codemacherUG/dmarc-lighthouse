import {
  buildSpfRecord,
  DEFAULT_SPF_BUILDER_INPUT,
  isValidDomain,
  listToLines,
  linesToList,
  normalizeDomain,
  normalizeSpfAll,
  parseSpfRecord,
  SPF_BUILDER_STEPS,
  spfRecordsEquivalent,
  spfStepIndex,
  type SpfAllQualifier,
  type SpfBuilderInput,
  type SpfBuilderStep
} from '../../shared/spf-builder'
import { t, type MessageKey } from '../../shared/i18n'
import type { SpfExpandResult } from '../../shared/types'
import {
  btnCloseSpfBuilder,
  btnSpfBuilder,
  btnSpfBuilderBack,
  btnSpfBuilderNext,
  dnsDomainEl,
  filterDomainEl,
  spfBuilderAllEl,
  spfBuilderDialog,
  spfBuilderDomainEl,
  spfBuilderDomainStatusEl,
  spfBuilderExpandEl,
  spfBuilderFooterHintEl,
  spfBuilderIncludesEl,
  spfBuilderIp4El,
  spfBuilderIp6El,
  spfBuilderLiveEl,
  spfBuilderResultEl,
  spfBuilderStepsEl,
  spfBuilderUseAEl,
  spfBuilderUseMxEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

let currentStep: SpfBuilderStep = 'domain'
let copyResetTimer: ReturnType<typeof setTimeout> | null = null
let liveDnsValue: string | null = null
let expandBusy = false
let dnsBusy = false

function readInput(): SpfBuilderInput {
  return {
    domain: normalizeDomain(spfBuilderDomainEl.value),
    includes: linesToList(spfBuilderIncludesEl.value),
    ip4: linesToList(spfBuilderIp4El.value),
    ip6: linesToList(spfBuilderIp6El.value),
    useA: spfBuilderUseAEl.checked,
    useMx: spfBuilderUseMxEl.checked,
    all: normalizeSpfAll(spfBuilderAllEl.value)
  }
}

function fillForm(input: Partial<SpfBuilderInput>): void {
  if (input.domain != null) spfBuilderDomainEl.value = input.domain
  if (input.includes != null) spfBuilderIncludesEl.value = listToLines(input.includes)
  if (input.ip4 != null) spfBuilderIp4El.value = listToLines(input.ip4)
  if (input.ip6 != null) spfBuilderIp6El.value = listToLines(input.ip6)
  if (input.useA != null) spfBuilderUseAEl.checked = input.useA
  if (input.useMx != null) spfBuilderUseMxEl.checked = input.useMx
  if (input.all != null) spfBuilderAllEl.value = input.all
}

function showStep(step: SpfBuilderStep): void {
  currentStep = step
  const idx = spfStepIndex(step)
  for (const li of spfBuilderStepsEl.querySelectorAll('li')) {
    const s = li.getAttribute('data-step') as SpfBuilderStep | null
    if (!s) continue
    const si = spfStepIndex(s)
    li.classList.toggle('active', s === step)
    li.classList.toggle('done', si >= 0 && si < idx)
  }
  for (const panel of document.querySelectorAll<HTMLElement>('.spf-builder-panel')) {
    panel.classList.toggle('hidden', panel.getAttribute('data-step') !== step)
  }
  btnSpfBuilderBack.disabled = step === 'domain'
  btnSpfBuilderNext.textContent = step === 'result' ? t('spfBuilder.finish') : t('spfBuilder.next')
  const input = readInput()
  spfBuilderFooterHintEl.textContent = input.domain || ''
  if (step === 'result') void renderResult()
}

function validateCurrentStep(): boolean {
  const input = readInput()
  if (currentStep === 'domain' && !isValidDomain(input.domain)) {
    spfBuilderDomainStatusEl.textContent = t('spfBuilder.error.domain')
    spfBuilderDomainStatusEl.className = 'builder-status error'
    return false
  }
  if (currentStep === 'mechanisms') {
    const hasMechanism =
      input.includes.length > 0 ||
      input.ip4.length > 0 ||
      input.ip6.length > 0 ||
      input.useA ||
      input.useMx
    if (!hasMechanism) {
      spfBuilderFooterHintEl.textContent = t('spfBuilder.error.mechanisms')
      return false
    }
  }
  spfBuilderDomainStatusEl.classList.remove('error')
  return true
}

function copyButton(value: string): string {
  return `<button type="button" class="btn secondary btn-copy" data-copy="${escapeHtml(value)}" data-label-key="spfBuilder.result.copy">${escapeHtml(t('spfBuilder.result.copy'))}</button>`
}

function renderExpand(result: SpfExpandResult | null, error?: string): void {
  if (error) {
    spfBuilderExpandEl.innerHTML = `<p class="builder-status error">${escapeHtml(error)}</p>`
    return
  }
  if (!result) {
    spfBuilderExpandEl.innerHTML = `<p class="hint">${escapeHtml(t('spfBuilder.expand.loading'))}</p>`
    return
  }
  const cidrList =
    result.cidrs.length > 0
      ? `<ul class="spf-expand-list mono">${result.cidrs.map((c) => `<li>${escapeHtml(c)}</li>`).join('')}</ul>`
      : `<p class="hint">${escapeHtml(t('spfBuilder.expand.empty'))}</p>`
  const errors =
    result.errors.length > 0
      ? `<div class="spf-expand-errors"><span class="builder-result-label">${escapeHtml(t('spfBuilder.expand.errors'))}</span><ul>${result.errors.map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul></div>`
      : ''
  spfBuilderExpandEl.innerHTML = `
    <article class="builder-result-card">
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('spfBuilder.expand.title'))}</span>
        <p class="hint">${escapeHtml(t('spfBuilder.expand.lookups', { count: String(result.lookups) }))}</p>
        ${cidrList}
      </div>
      ${errors}
    </article>`
}

async function renderResult(): Promise<void> {
  const input = readInput()
  const record = buildSpfRecord(input)

  spfBuilderResultEl.innerHTML = `
    <article class="builder-result-card">
      <div class="builder-result-top">
        <div class="builder-result-field">
          <span class="builder-result-label">${escapeHtml(t('spfBuilder.result.host'))}</span>
          <div class="builder-result-row">
            <code class="mono">${escapeHtml(record.host)}</code>
            ${copyButton(record.host)}
          </div>
        </div>
        <div class="builder-result-field builder-result-type">
          <span class="builder-result-label">${escapeHtml(t('spfBuilder.result.type'))}</span>
          <code class="mono">${escapeHtml(record.type)}</code>
        </div>
      </div>
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('spfBuilder.result.value'))}</span>
        <div class="builder-result-value">
          <code class="mono">${escapeHtml(record.value)}</code>
          ${copyButton(record.value)}
        </div>
      </div>
      <div class="builder-result-tags">
        <span class="builder-result-label">${escapeHtml(t('spfBuilder.result.terms'))}</span>
        <div class="builder-tag-list">
          ${record.terms
            .map((term) => {
              const label =
                term.key === 'v'
                  ? `v=${term.value}`
                  : term.key === 'all'
                    ? (term.value as SpfAllQualifier)
                    : term.value
                      ? `${term.key}:${term.value}`
                      : term.key
              return `<span class="builder-tag mono">${escapeHtml(label)}</span>`
            })
            .join('')}
        </div>
      </div>
    </article>`

  if (!liveDnsValue) {
    spfBuilderLiveEl.innerHTML = `<p class="hint">${escapeHtml(t('spfBuilder.result.liveMissing'))}</p>`
  } else {
    const same = spfRecordsEquivalent(liveDnsValue, record.value)
    spfBuilderLiveEl.innerHTML = `<div class="builder-live-card">
      <span class="builder-result-label">${escapeHtml(t('spfBuilder.result.liveTitle'))}</span>
      <code class="mono">${escapeHtml(liveDnsValue)}</code>
      <p class="hint">${escapeHtml(same ? t('spfBuilder.result.liveSame') : t('spfBuilder.result.liveDifferent'))}</p>
    </div>`
  }

  renderExpand(null)
  if (expandBusy) return
  expandBusy = true
  try {
    if (typeof window.api.expandSpf !== 'function') {
      renderExpand(null, t('spfBuilder.expand.needRestart'))
      return
    }
    const expanded = await window.api.expandSpf(record.domain, record.value)
    renderExpand(expanded)
  } catch (err) {
    renderExpand(null, err instanceof Error ? err.message : String(err))
  } finally {
    expandBusy = false
  }
}

/** Load live SPF into the form. Always continues afterward (missing/error keeps defaults). */
async function loadDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(spfBuilderDomainEl.value)
  spfBuilderDomainEl.value = domain
  spfBuilderDomainStatusEl.textContent = t('spfBuilder.domain.loading', { domain })
  spfBuilderDomainStatusEl.className = 'builder-status'
  try {
    const result = await window.api.checkDns(domain)
    spfBuilderDomainEl.value = result.domain
    const existing =
      result.spf.records.find((r) => /v\s*=\s*spf1/i.test(r)) ?? result.spf.records[0] ?? null
    liveDnsValue = existing
    if (existing) {
      fillForm({ domain: result.domain, ...parseSpfRecord(existing) })
      spfBuilderDomainStatusEl.textContent = t('spfBuilder.domain.loaded')
      spfBuilderDomainStatusEl.className = 'builder-status ok'
    } else {
      liveDnsValue = null
      fillForm({ domain: result.domain })
      spfBuilderDomainStatusEl.textContent = t('spfBuilder.domain.missing')
      spfBuilderDomainStatusEl.className = 'builder-status'
    }
  } catch (err) {
    liveDnsValue = null
    spfBuilderDomainStatusEl.textContent = t('spfBuilder.domain.error', {
      message: err instanceof Error ? err.message : String(err)
    })
    spfBuilderDomainStatusEl.className = 'builder-status error'
  }
}

function suggestInitialDomain(): string {
  const fromDns = dnsDomainEl.value.trim()
  if (fromDns) return normalizeDomain(fromDns)
  const fromFilter = filterDomainEl.value.trim()
  if (fromFilter) return normalizeDomain(fromFilter)
  const domains = state.fullResult?.aggregate.domains ?? []
  return domains[0] ? normalizeDomain(domains[0]) : ''
}

export function openSpfBuilder(): void {
  fillForm({ ...DEFAULT_SPF_BUILDER_INPUT })
  const domain = suggestInitialDomain()
  if (domain) spfBuilderDomainEl.value = domain
  liveDnsValue = null
  spfBuilderDomainStatusEl.textContent = ''
  spfBuilderDomainStatusEl.className = 'builder-status muted'
  spfBuilderLiveEl.textContent = ''
  spfBuilderExpandEl.textContent = ''
  showStep('domain')
  spfBuilderDialog.showModal()
  spfBuilderDomainEl.focus()
}

export function refreshSpfBuilderLocale(): void {
  if (!spfBuilderDialog.open) return
  showStep(currentStep)
}

export function initSpfWizardUi(): void {
  btnSpfBuilder.addEventListener('click', () => openSpfBuilder())
  btnCloseSpfBuilder.addEventListener('click', () => spfBuilderDialog.close())

  btnSpfBuilderBack.addEventListener('click', () => {
    const idx = spfStepIndex(currentStep)
    if (idx > 0) showStep(SPF_BUILDER_STEPS[idx - 1])
  })

  btnSpfBuilderNext.addEventListener('click', () => {
    void (async () => {
      if (dnsBusy) return
      if (currentStep === 'result') {
        spfBuilderDialog.close()
        return
      }
      if (!validateCurrentStep()) return
      if (currentStep === 'domain') {
        dnsBusy = true
        btnSpfBuilderNext.disabled = true
        try {
          await loadDnsTemplate()
        } finally {
          dnsBusy = false
          btnSpfBuilderNext.disabled = false
        }
      }
      const idx = spfStepIndex(currentStep)
      showStep(SPF_BUILDER_STEPS[idx + 1])
    })()
  })

  spfBuilderResultEl.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null
    const btn = target?.closest?.('.btn-copy') as HTMLButtonElement | null
    if (!btn) return
    const value = btn.getAttribute('data-copy') ?? ''
    void navigator.clipboard.writeText(value).then(() => {
      const labelKey = (btn.getAttribute('data-label-key') ||
        'spfBuilder.result.copy') as MessageKey
      btn.textContent = t('spfBuilder.result.copied')
      if (copyResetTimer) clearTimeout(copyResetTimer)
      copyResetTimer = setTimeout(() => {
        btn.textContent = t(labelKey)
      }, 1500)
    })
  })
}
