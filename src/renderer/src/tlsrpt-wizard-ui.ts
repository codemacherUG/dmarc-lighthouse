import {
  buildTlsRptRecord,
  DEFAULT_TLSRPT_BUILDER_INPUT,
  defaultTlsRptMailbox,
  normalizeDomain,
  parseTlsRptBuilderRecord,
  TLSRPT_BUILDER_STEPS,
  tlsrptRecordsEquivalent,
  tlsrptStepIndex,
  validateTlsRptBuilderStep,
  type TlsRptBuilderInput,
  type TlsRptBuilderStep
} from '../../shared/tlsrpt-builder'
import { t, type MessageKey } from '../../shared/i18n'
import {
  btnCloseTlsrptBuilder,
  btnTlsrptBuilder,
  btnTlsrptBuilderBack,
  btnTlsrptBuilderNext,
  dnsDomainEl,
  filterDomainEl,
  tlsrptBuilderDialog,
  tlsrptBuilderDomainEl,
  tlsrptBuilderDomainStatusEl,
  tlsrptBuilderFooterHintEl,
  tlsrptBuilderLiveEl,
  tlsrptBuilderResultEl,
  tlsrptBuilderRuaEl,
  tlsrptBuilderStepsEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

let currentStep: TlsRptBuilderStep = 'domain'
let copyResetTimer: ReturnType<typeof setTimeout> | null = null
let liveDnsValue: string | null = null
let dnsBusy = false

function readInput(): TlsRptBuilderInput {
  return {
    domain: normalizeDomain(tlsrptBuilderDomainEl.value),
    rua: tlsrptBuilderRuaEl.value.trim()
  }
}

function fillForm(input: Partial<TlsRptBuilderInput>): void {
  if (input.domain != null) tlsrptBuilderDomainEl.value = input.domain
  if (input.rua != null) tlsrptBuilderRuaEl.value = input.rua
}

function centerActiveStep(list: HTMLElement): void {
  const active = list.querySelector<HTMLElement>('li.active')
  if (!active) return
  const listRect = list.getBoundingClientRect()
  const activeRect = active.getBoundingClientRect()
  const left =
    list.scrollLeft + (activeRect.left - listRect.left) - (list.clientWidth - activeRect.width) / 2
  list.scrollTo({ left: Math.max(0, left), behavior: 'smooth' })
}

function showStep(step: TlsRptBuilderStep): void {
  currentStep = step
  const idx = tlsrptStepIndex(step)
  for (const li of tlsrptBuilderStepsEl.querySelectorAll('li')) {
    const s = li.getAttribute('data-step') as TlsRptBuilderStep | null
    if (!s) continue
    const si = tlsrptStepIndex(s)
    li.classList.toggle('active', s === step)
    li.classList.toggle('done', si >= 0 && si < idx)
  }
  centerActiveStep(tlsrptBuilderStepsEl)
  for (const panel of document.querySelectorAll<HTMLElement>('.tlsrpt-builder-panel')) {
    panel.classList.toggle('hidden', panel.getAttribute('data-step') !== step)
  }
  btnTlsrptBuilderBack.disabled = step === 'domain'
  btnTlsrptBuilderNext.textContent =
    step === 'result' ? t('tlsrptBuilder.finish') : t('tlsrptBuilder.next')
  const input = readInput()
  tlsrptBuilderFooterHintEl.textContent = input.domain || ''
  if (step === 'result') renderResult()
}

function validateCurrentStep(): boolean {
  const input = readInput()
  const error = validateTlsRptBuilderStep(currentStep, input)
  if (!error) {
    tlsrptBuilderDomainStatusEl.classList.remove('error')
    return true
  }
  const message = t(error as MessageKey)
  if (currentStep === 'domain') {
    tlsrptBuilderDomainStatusEl.textContent = message
    tlsrptBuilderDomainStatusEl.className = 'builder-status error'
  } else {
    tlsrptBuilderFooterHintEl.textContent = message
  }
  return false
}

function copyButton(value: string): string {
  return `<button type="button" class="btn secondary btn-copy" data-copy="${escapeHtml(value)}" data-label-key="tlsrptBuilder.result.copy">${escapeHtml(t('tlsrptBuilder.result.copy'))}</button>`
}

function renderResult(): void {
  const input = readInput()
  const record = buildTlsRptRecord(input)

  tlsrptBuilderResultEl.innerHTML = `
    <article class="builder-result-card">
      <div class="builder-result-top">
        <div class="builder-result-field">
          <span class="builder-result-label">${escapeHtml(t('tlsrptBuilder.result.host'))}</span>
          <div class="builder-result-row">
            <code class="mono">${escapeHtml(record.host)}</code>
            ${copyButton(record.host)}
          </div>
        </div>
        <div class="builder-result-field builder-result-type">
          <span class="builder-result-label">${escapeHtml(t('tlsrptBuilder.result.type'))}</span>
          <code class="mono">${escapeHtml(record.type)}</code>
        </div>
      </div>
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('tlsrptBuilder.result.value'))}</span>
        <div class="builder-result-value">
          <code class="mono">${escapeHtml(record.value)}</code>
          ${copyButton(record.value)}
        </div>
      </div>
      <div class="builder-result-tags">
        <span class="builder-result-label">${escapeHtml(t('tlsrptBuilder.result.tags'))}</span>
        <div class="builder-tag-list">
          ${record.tags
            .map(
              (tag) =>
                `<span class="builder-tag mono">${escapeHtml(tag.key)}=${escapeHtml(tag.value)}</span>`
            )
            .join('')}
        </div>
      </div>
    </article>`

  if (!liveDnsValue) {
    tlsrptBuilderLiveEl.innerHTML = `<p class="hint">${escapeHtml(t('tlsrptBuilder.result.liveMissing'))}</p>`
    return
  }
  const same = tlsrptRecordsEquivalent(liveDnsValue, record.value)
  tlsrptBuilderLiveEl.innerHTML = `<div class="builder-live-card">
    <span class="builder-result-label">${escapeHtml(t('tlsrptBuilder.result.liveTitle'))}</span>
    <code class="mono">${escapeHtml(liveDnsValue)}</code>
    <p class="hint">${escapeHtml(same ? t('tlsrptBuilder.result.liveSame') : t('tlsrptBuilder.result.liveDifferent'))}</p>
  </div>`
}

function ensureDefaultMailbox(domain: string): void {
  const mailbox = defaultTlsRptMailbox(domain)
  if (!mailbox) return
  if (!tlsrptBuilderRuaEl.value.trim()) tlsrptBuilderRuaEl.value = mailbox
}

async function loadDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(tlsrptBuilderDomainEl.value)
  tlsrptBuilderDomainEl.value = domain
  tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.loading', { domain })
  tlsrptBuilderDomainStatusEl.className = 'builder-status'
  try {
    const result = await window.api.checkTransport(domain)
    tlsrptBuilderDomainEl.value = result.domain
    ensureDefaultMailbox(result.domain)
    const existing =
      result.tlsrpt.records.find((r) => /v\s*=\s*TLSRPTv1/i.test(r)) ??
      result.tlsrpt.records[0] ??
      null
    liveDnsValue = existing
    if (existing) {
      fillForm({ domain: result.domain, ...parseTlsRptBuilderRecord(existing) })
      tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.loaded')
      tlsrptBuilderDomainStatusEl.className = 'builder-status ok'
    } else {
      liveDnsValue = null
      fillForm({ domain: result.domain })
      tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.missing')
      tlsrptBuilderDomainStatusEl.className = 'builder-status'
    }
  } catch (err) {
    liveDnsValue = null
    tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.error', {
      message: err instanceof Error ? err.message : String(err)
    })
    tlsrptBuilderDomainStatusEl.className = 'builder-status error'
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

export function openTlsrptBuilder(): void {
  fillForm({ ...DEFAULT_TLSRPT_BUILDER_INPUT })
  const domain = suggestInitialDomain()
  if (domain) {
    tlsrptBuilderDomainEl.value = domain
    ensureDefaultMailbox(domain)
  }
  liveDnsValue = null
  tlsrptBuilderDomainStatusEl.textContent = ''
  tlsrptBuilderDomainStatusEl.className = 'builder-status muted'
  tlsrptBuilderLiveEl.textContent = ''
  showStep('domain')
  tlsrptBuilderDialog.showModal()
  tlsrptBuilderDomainEl.focus()
}

export function refreshTlsrptBuilderLocale(): void {
  if (!tlsrptBuilderDialog.open) return
  showStep(currentStep)
}

export function initTlsrptWizardUi(): void {
  btnTlsrptBuilder.addEventListener('click', () => openTlsrptBuilder())
  btnCloseTlsrptBuilder.addEventListener('click', () => tlsrptBuilderDialog.close())

  btnTlsrptBuilderBack.addEventListener('click', () => {
    const idx = tlsrptStepIndex(currentStep)
    if (idx > 0) showStep(TLSRPT_BUILDER_STEPS[idx - 1])
  })

  btnTlsrptBuilderNext.addEventListener('click', () => {
    void (async () => {
      if (dnsBusy) return
      if (currentStep === 'result') {
        tlsrptBuilderDialog.close()
        return
      }
      if (!validateCurrentStep()) return
      if (currentStep === 'domain') {
        const domain = normalizeDomain(tlsrptBuilderDomainEl.value)
        tlsrptBuilderDomainEl.value = domain
        ensureDefaultMailbox(domain)
        dnsBusy = true
        btnTlsrptBuilderNext.disabled = true
        try {
          await loadDnsTemplate()
        } finally {
          dnsBusy = false
          btnTlsrptBuilderNext.disabled = false
        }
      }
      const idx = tlsrptStepIndex(currentStep)
      showStep(TLSRPT_BUILDER_STEPS[idx + 1])
    })()
  })

  tlsrptBuilderDomainEl.addEventListener('change', () => {
    const domain = normalizeDomain(tlsrptBuilderDomainEl.value)
    if (domain) ensureDefaultMailbox(domain)
  })

  tlsrptBuilderResultEl.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null
    const btn = target?.closest?.('.btn-copy') as HTMLButtonElement | null
    if (!btn) return
    const value = btn.getAttribute('data-copy') ?? ''
    void navigator.clipboard.writeText(value).then(() => {
      const labelKey = (btn.getAttribute('data-label-key') ||
        'tlsrptBuilder.result.copy') as MessageKey
      btn.textContent = t('tlsrptBuilder.result.copied')
      if (copyResetTimer) clearTimeout(copyResetTimer)
      copyResetTimer = setTimeout(() => {
        btn.textContent = t(labelKey)
      }, 1500)
    })
  })
}
