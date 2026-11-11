import {
  buildTlsRptRecord,
  DEFAULT_TLSRPT_BUILDER_INPUT,
  defaultTlsRptMailbox,
  isValidDomain,
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
  tlsrptBuilderDialog,
  tlsrptBuilderDomainEl,
  tlsrptBuilderDomainStatusEl,
  tlsrptBuilderFooterHintEl,
  tlsrptBuilderLiveEl,
  tlsrptBuilderPreviewEl,
  tlsrptBuilderResultEl,
  tlsrptBuilderRuaEl,
  tlsrptBuilderStepsEl
} from './dom'
import { escapeHtml } from './format'
import {
  bindWizardCopyButtons,
  createInflightDeduper,
  suggestInitialWizardDomain,
  syncWizardStepDom,
  wizardCopyButtonHtml
} from './wizard-common'

let currentStep: TlsRptBuilderStep = 'domain'
let liveDnsValue: string | null = null
let loadGen = 0
let appliedKey = ''
const templateDeduper = createInflightDeduper()

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

function showStep(step: TlsRptBuilderStep): void {
  currentStep = step
  syncWizardStepDom({
    stepsEl: tlsrptBuilderStepsEl,
    panelSelector: '.tlsrpt-builder-panel',
    backBtn: btnTlsrptBuilderBack,
    nextBtn: btnTlsrptBuilderNext,
    step,
    stepIndex: tlsrptStepIndex,
    finishKey: 'tlsrptBuilder.finish',
    nextKey: 'tlsrptBuilder.next'
  })
  const input = readInput()
  tlsrptBuilderFooterHintEl.textContent = input.domain || ''
  if (step === 'domain') renderDomainPreview()
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
  return wizardCopyButtonHtml(value, 'tlsrptBuilder.result.copy')
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

function renderDomainPreview(): void {
  if (!liveDnsValue) {
    tlsrptBuilderPreviewEl.innerHTML = ''
    return
  }
  tlsrptBuilderPreviewEl.innerHTML = `<div class="builder-live-card">
    <span class="builder-result-label">${escapeHtml(t('tlsrptBuilder.result.liveTitle'))}</span>
    <code class="mono">${escapeHtml(liveDnsValue)}</code>
  </div>`
}

function applyTlsrptTemplate(domain: string, record: string | null): void {
  if (record) {
    fillForm({ domain, ...parseTlsRptBuilderRecord(record) })
    return
  }
  fillForm({ domain, rua: defaultTlsRptMailbox(domain) })
}

async function loadDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(tlsrptBuilderDomainEl.value)
  if (!isValidDomain(domain)) return
  if (appliedKey === domain) return

  const gen = ++loadGen
  tlsrptBuilderDomainEl.value = domain
  tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.loading', { domain })
  tlsrptBuilderDomainStatusEl.className = 'builder-status'
  try {
    const result = await window.api.checkTransport(domain)
    if (gen !== loadGen) return
    tlsrptBuilderDomainEl.value = result.domain
    const existing =
      result.tlsrpt.records.find((r) => /v\s*=\s*TLSRPTv1/i.test(r)) ??
      result.tlsrpt.records[0] ??
      null
    liveDnsValue = result.tlsrpt.found ? existing : null
    appliedKey = result.domain
    applyTlsrptTemplate(result.domain, liveDnsValue)
    if (liveDnsValue) {
      tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.loaded')
      tlsrptBuilderDomainStatusEl.className = 'builder-status ok'
    } else {
      tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.missing')
      tlsrptBuilderDomainStatusEl.className = 'builder-status'
    }
    renderDomainPreview()
  } catch (err) {
    if (gen !== loadGen) return
    liveDnsValue = null
    appliedKey = ''
    tlsrptBuilderPreviewEl.innerHTML = ''
    tlsrptBuilderDomainStatusEl.textContent = t('tlsrptBuilder.domain.error', {
      message: err instanceof Error ? err.message : String(err)
    })
    tlsrptBuilderDomainStatusEl.className = 'builder-status error'
  }
}

function requestDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(tlsrptBuilderDomainEl.value)
  return templateDeduper.run(domain, loadDnsTemplate)
}

export function openTlsrptBuilder(): void {
  fillForm({ ...DEFAULT_TLSRPT_BUILDER_INPUT })
  const domain = suggestInitialWizardDomain()
  if (domain) {
    tlsrptBuilderDomainEl.value = domain
    ensureDefaultMailbox(domain)
  }
  liveDnsValue = null
  appliedKey = ''
  loadGen += 1
  tlsrptBuilderDomainStatusEl.textContent = ''
  tlsrptBuilderDomainStatusEl.className = 'builder-status muted'
  tlsrptBuilderPreviewEl.innerHTML = ''
  tlsrptBuilderLiveEl.textContent = ''
  showStep('domain')
  tlsrptBuilderDialog.showModal()
  tlsrptBuilderDomainEl.focus()
  if (isValidDomain(domain)) void requestDnsTemplate()
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
      if (currentStep === 'result') {
        tlsrptBuilderDialog.close()
        return
      }
      if (!validateCurrentStep()) return
      btnTlsrptBuilderNext.disabled = true
      try {
        if (currentStep === 'domain') await requestDnsTemplate()
      } finally {
        btnTlsrptBuilderNext.disabled = false
      }
      const idx = tlsrptStepIndex(currentStep)
      showStep(TLSRPT_BUILDER_STEPS[idx + 1])
    })()
  })

  tlsrptBuilderDomainEl.addEventListener('change', () => {
    const domain = normalizeDomain(tlsrptBuilderDomainEl.value)
    tlsrptBuilderDomainEl.value = domain
    appliedKey = ''
    if (isValidDomain(domain)) void requestDnsTemplate()
    else if (domain) ensureDefaultMailbox(domain)
  })

  bindWizardCopyButtons(
    tlsrptBuilderResultEl,
    'tlsrptBuilder.result.copy',
    'tlsrptBuilder.result.copied'
  )
}
