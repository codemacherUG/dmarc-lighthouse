import {
  buildMtaStsPolicyFile,
  buildMtaStsRecord,
  DEFAULT_MTA_STS_BUILDER_INPUT,
  listToLines,
  linesToList,
  MTA_STS_BUILDER_STEPS,
  MTA_STS_MAX_AGE_DEFAULT,
  mtaStsPoliciesEquivalent,
  mtaStsStepIndex,
  normalizeDomain,
  isValidDomain,
  normalizeMaxAge,
  normalizeMtaStsMode,
  parseMtaStsBuilderPolicy,
  parseMtaStsBuilderTxt,
  validateMtaStsBuilderStep,
  type MtaStsBuilderInput,
  type MtaStsBuilderStep
} from '../../shared/mta-sts-builder'
import { t, type MessageKey } from '../../shared/i18n'
import {
  btnCloseMtaStsBuilder,
  btnMtaStsBuilder,
  btnMtaStsBuilderBack,
  btnMtaStsBuilderNext,
  dnsDomainEl,
  filterDomainEl,
  mtaStsBuilderDialog,
  mtaStsBuilderDomainEl,
  mtaStsBuilderDomainStatusEl,
  mtaStsBuilderFooterHintEl,
  mtaStsBuilderLiveEl,
  mtaStsBuilderPreviewEl,
  mtaStsBuilderMaxAgeEl,
  mtaStsBuilderModeEl,
  mtaStsBuilderMxEl,
  mtaStsBuilderRenewIdEl,
  mtaStsBuilderResultEl,
  mtaStsBuilderStepsEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

let currentStep: MtaStsBuilderStep = 'domain'
let copyResetTimer: ReturnType<typeof setTimeout> | null = null
let liveDnsValue: string | null = null
let livePolicyText: string | null = null
let liveId: string | null = null
let loadGen = 0
let appliedKey = ''
let inflight: Promise<void> | null = null
let inflightKey = ''

function readInput(): MtaStsBuilderInput {
  return {
    domain: normalizeDomain(mtaStsBuilderDomainEl.value),
    mode: normalizeMtaStsMode(mtaStsBuilderModeEl.value),
    mx: linesToList(mtaStsBuilderMxEl.value),
    maxAgeSeconds: normalizeMaxAge(mtaStsBuilderMaxAgeEl.value),
    id: ''
  }
}

function fillForm(input: Partial<MtaStsBuilderInput>): void {
  if (input.domain != null) mtaStsBuilderDomainEl.value = input.domain
  if (input.mode != null) mtaStsBuilderModeEl.value = input.mode
  if (input.mx != null) mtaStsBuilderMxEl.value = listToLines(input.mx)
  if (input.maxAgeSeconds != null) mtaStsBuilderMaxAgeEl.value = String(input.maxAgeSeconds)
}

function resolvedId(input: MtaStsBuilderInput): string {
  const renew = mtaStsBuilderRenewIdEl.checked
  if (
    !renew &&
    liveId &&
    livePolicyText &&
    mtaStsPoliciesEquivalent(input, parseMtaStsBuilderPolicy(livePolicyText))
  ) {
    return liveId
  }
  return ''
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

function showStep(step: MtaStsBuilderStep): void {
  currentStep = step
  const idx = mtaStsStepIndex(step)
  for (const li of mtaStsBuilderStepsEl.querySelectorAll('li')) {
    const s = li.getAttribute('data-step') as MtaStsBuilderStep | null
    if (!s) continue
    const si = mtaStsStepIndex(s)
    li.classList.toggle('active', s === step)
    li.classList.toggle('done', si >= 0 && si < idx)
  }
  centerActiveStep(mtaStsBuilderStepsEl)
  for (const panel of document.querySelectorAll<HTMLElement>('.mta-sts-builder-panel')) {
    panel.classList.toggle('hidden', panel.getAttribute('data-step') !== step)
  }
  btnMtaStsBuilderBack.disabled = step === 'domain'
  btnMtaStsBuilderNext.textContent =
    step === 'result' ? t('mtaStsBuilder.finish') : t('mtaStsBuilder.next')
  const input = readInput()
  mtaStsBuilderFooterHintEl.textContent = input.domain || ''
  if (step === 'domain') renderDomainPreview()
  if (step === 'result') renderResult()
}

function validateCurrentStep(): boolean {
  const input = readInput()
  const error = validateMtaStsBuilderStep(currentStep, input)
  if (!error) {
    mtaStsBuilderDomainStatusEl.classList.remove('error')
    return true
  }
  const message = t(error as MessageKey)
  if (currentStep === 'domain') {
    mtaStsBuilderDomainStatusEl.textContent = message
    mtaStsBuilderDomainStatusEl.className = 'builder-status error'
  } else {
    mtaStsBuilderFooterHintEl.textContent = message
  }
  return false
}

function copyButton(value: string, labelKey: MessageKey = 'mtaStsBuilder.result.copy'): string {
  return `<button type="button" class="btn secondary btn-copy" data-copy="${escapeHtml(value)}" data-label-key="${escapeHtml(labelKey)}">${escapeHtml(t(labelKey))}</button>`
}

function renderResult(): void {
  const input = readInput()
  const record = buildMtaStsRecord({ ...input, id: resolvedId(input) })

  mtaStsBuilderResultEl.innerHTML = `
    <article class="builder-result-card">
      <div class="builder-result-top">
        <div class="builder-result-field">
          <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.host'))}</span>
          <div class="builder-result-row">
            <code class="mono">${escapeHtml(record.dns.host)}</code>
            ${copyButton(record.dns.host)}
          </div>
        </div>
        <div class="builder-result-field builder-result-type">
          <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.type'))}</span>
          <code class="mono">${escapeHtml(record.dns.type)}</code>
        </div>
      </div>
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.value'))}</span>
        <div class="builder-result-value">
          <code class="mono">${escapeHtml(record.dns.value)}</code>
          ${copyButton(record.dns.value)}
        </div>
      </div>
      <p class="hint">${escapeHtml(t('mtaStsBuilder.result.dnsHint'))}</p>
    </article>
    <article class="builder-result-card">
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.policyUrl'))}</span>
        <div class="builder-result-row">
          <code class="mono">${escapeHtml(record.policyUrl)}</code>
          ${copyButton(record.policyUrl)}
        </div>
      </div>
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.httpsHost'))}</span>
        <div class="builder-result-row">
          <code class="mono">${escapeHtml(record.httpsHost)}</code>
          ${copyButton(record.httpsHost)}
        </div>
      </div>
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.policyFile'))}</span>
        <div class="builder-result-value">
          <code class="mono">${escapeHtml(record.policyText.trimEnd())}</code>
          ${copyButton(record.policyText)}
        </div>
      </div>
      <p class="hint">${escapeHtml(t('mtaStsBuilder.result.httpsHint'))}</p>
    </article>`

  const liveBits: string[] = []
  if (liveDnsValue) {
    const sameTxt = liveDnsValue.replace(/\s+/g, '') === record.dns.value.replace(/\s+/g, '')
    liveBits.push(`<div class="builder-live-card">
      <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.liveTxtTitle'))}</span>
      <code class="mono">${escapeHtml(liveDnsValue)}</code>
      <p class="hint">${escapeHtml(sameTxt ? t('mtaStsBuilder.result.liveSame') : t('mtaStsBuilder.result.liveDifferent'))}</p>
    </div>`)
  } else {
    liveBits.push(`<p class="hint">${escapeHtml(t('mtaStsBuilder.result.liveTxtMissing'))}</p>`)
  }
  if (livePolicyText) {
    const samePolicy = mtaStsPoliciesEquivalent(input, parseMtaStsBuilderPolicy(livePolicyText))
    liveBits.push(`<div class="builder-live-card">
      <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.livePolicyTitle'))}</span>
      <code class="mono">${escapeHtml(livePolicyText.trimEnd())}</code>
      <p class="hint">${escapeHtml(samePolicy ? t('mtaStsBuilder.result.liveSame') : t('mtaStsBuilder.result.liveDifferent'))}</p>
    </div>`)
  } else {
    liveBits.push(`<p class="hint">${escapeHtml(t('mtaStsBuilder.result.livePolicyMissing'))}</p>`)
  }
  mtaStsBuilderLiveEl.innerHTML = liveBits.join('')
}

function renderDomainPreview(): void {
  const bits: string[] = []
  if (liveDnsValue) {
    bits.push(`<div class="builder-live-card">
      <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.liveTxtTitle'))}</span>
      <code class="mono">${escapeHtml(liveDnsValue)}</code>
    </div>`)
  }
  if (livePolicyText) {
    bits.push(`<div class="builder-live-card">
      <span class="builder-result-label">${escapeHtml(t('mtaStsBuilder.result.livePolicyTitle'))}</span>
      <code class="mono">${escapeHtml(livePolicyText.trimEnd())}</code>
    </div>`)
  }
  mtaStsBuilderPreviewEl.innerHTML = bits.join('')
}

async function loadDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(mtaStsBuilderDomainEl.value)
  if (!isValidDomain(domain)) return
  if (appliedKey === domain) return

  const gen = ++loadGen
  mtaStsBuilderDomainEl.value = domain
  mtaStsBuilderDomainStatusEl.textContent = t('mtaStsBuilder.domain.loading', { domain })
  mtaStsBuilderDomainStatusEl.className = 'builder-status'
  try {
    const result = await window.api.checkTransport(domain)
    if (gen !== loadGen) return
    mtaStsBuilderDomainEl.value = result.domain
    const existingTxt =
      result.mtaSts.records.find((r) => /v\s*=\s*STSv1/i.test(r)) ??
      result.mtaSts.records[0] ??
      null
    const mxFromPolicy = result.mtaSts.policy?.mx ?? []
    const mxFromDns = result.dane.mx.map((m) => m.host)
    liveDnsValue = result.mtaSts.found ? existingTxt : null
    liveId = result.mtaSts.id
    livePolicyText = result.mtaSts.policy
      ? buildMtaStsPolicyFile({
          ...DEFAULT_MTA_STS_BUILDER_INPUT,
          domain: result.domain,
          mode: result.mtaSts.policy.mode ?? 'testing',
          mx: result.mtaSts.policy.mx,
          maxAgeSeconds: result.mtaSts.policy.maxAgeSeconds ?? MTA_STS_MAX_AGE_DEFAULT
        })
      : null

    const parsedTxt = liveDnsValue ? parseMtaStsBuilderTxt(liveDnsValue) : {}
    const parsedPolicy = livePolicyText ? parseMtaStsBuilderPolicy(livePolicyText) : {}
    fillForm({
      domain: result.domain,
      mode: parsedPolicy.mode ?? DEFAULT_MTA_STS_BUILDER_INPUT.mode,
      maxAgeSeconds: parsedPolicy.maxAgeSeconds ?? DEFAULT_MTA_STS_BUILDER_INPUT.maxAgeSeconds,
      mx: mxFromPolicy.length > 0 ? mxFromPolicy : mxFromDns,
      ...parsedTxt
    })
    appliedKey = result.domain

    if (liveDnsValue && livePolicyText) {
      mtaStsBuilderDomainStatusEl.textContent = t('mtaStsBuilder.domain.loaded')
      mtaStsBuilderDomainStatusEl.className = 'builder-status ok'
    } else if (liveDnsValue) {
      mtaStsBuilderDomainStatusEl.textContent = t('mtaStsBuilder.domain.loadedTxtOnly')
      mtaStsBuilderDomainStatusEl.className = 'builder-status'
    } else if (mxFromDns.length > 0) {
      liveDnsValue = null
      liveId = null
      livePolicyText = null
      mtaStsBuilderDomainStatusEl.textContent = t('mtaStsBuilder.domain.missingMx')
      mtaStsBuilderDomainStatusEl.className = 'builder-status'
    } else {
      liveDnsValue = null
      liveId = null
      livePolicyText = null
      mtaStsBuilderDomainStatusEl.textContent = t('mtaStsBuilder.domain.missing')
      mtaStsBuilderDomainStatusEl.className = 'builder-status'
    }
    renderDomainPreview()
  } catch (err) {
    if (gen !== loadGen) return
    liveDnsValue = null
    liveId = null
    livePolicyText = null
    appliedKey = ''
    mtaStsBuilderPreviewEl.innerHTML = ''
    mtaStsBuilderDomainStatusEl.textContent = t('mtaStsBuilder.domain.error', {
      message: err instanceof Error ? err.message : String(err)
    })
    mtaStsBuilderDomainStatusEl.className = 'builder-status error'
  }
}

function requestDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(mtaStsBuilderDomainEl.value)
  if (inflight && inflightKey === domain) return inflight
  inflightKey = domain
  inflight = loadDnsTemplate().finally(() => {
    if (inflightKey === domain) inflight = null
  })
  return inflight
}

function suggestInitialDomain(): string {
  const fromDns = dnsDomainEl.value.trim()
  if (fromDns) return normalizeDomain(fromDns)
  const fromFilter = filterDomainEl.value.trim()
  if (fromFilter) return normalizeDomain(fromFilter)
  const domains = state.fullResult?.aggregate.domains ?? []
  return domains[0] ? normalizeDomain(domains[0]) : ''
}

export function openMtaStsBuilder(): void {
  fillForm({ ...DEFAULT_MTA_STS_BUILDER_INPUT })
  mtaStsBuilderRenewIdEl.checked = false
  const domain = suggestInitialDomain()
  if (domain) mtaStsBuilderDomainEl.value = domain
  liveDnsValue = null
  livePolicyText = null
  liveId = null
  appliedKey = ''
  loadGen += 1
  mtaStsBuilderDomainStatusEl.textContent = ''
  mtaStsBuilderDomainStatusEl.className = 'builder-status muted'
  mtaStsBuilderPreviewEl.innerHTML = ''
  mtaStsBuilderLiveEl.textContent = ''
  showStep('domain')
  mtaStsBuilderDialog.showModal()
  mtaStsBuilderDomainEl.focus()
  if (isValidDomain(domain)) void requestDnsTemplate()
}

export function refreshMtaStsBuilderLocale(): void {
  if (!mtaStsBuilderDialog.open) return
  showStep(currentStep)
}

export function initMtaStsWizardUi(): void {
  btnMtaStsBuilder.addEventListener('click', () => openMtaStsBuilder())
  btnCloseMtaStsBuilder.addEventListener('click', () => mtaStsBuilderDialog.close())

  btnMtaStsBuilderBack.addEventListener('click', () => {
    const idx = mtaStsStepIndex(currentStep)
    if (idx > 0) showStep(MTA_STS_BUILDER_STEPS[idx - 1])
  })

  btnMtaStsBuilderNext.addEventListener('click', () => {
    void (async () => {
      if (currentStep === 'result') {
        mtaStsBuilderDialog.close()
        return
      }
      if (!validateCurrentStep()) return
      btnMtaStsBuilderNext.disabled = true
      try {
        if (currentStep === 'domain') await requestDnsTemplate()
      } finally {
        btnMtaStsBuilderNext.disabled = false
      }
      const idx = mtaStsStepIndex(currentStep)
      showStep(MTA_STS_BUILDER_STEPS[idx + 1])
    })()
  })

  mtaStsBuilderDomainEl.addEventListener('change', () => {
    const domain = normalizeDomain(mtaStsBuilderDomainEl.value)
    mtaStsBuilderDomainEl.value = domain
    appliedKey = ''
    if (isValidDomain(domain)) void requestDnsTemplate()
  })

  mtaStsBuilderResultEl.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null
    const btn = target?.closest?.('.btn-copy') as HTMLButtonElement | null
    if (!btn) return
    const value = btn.getAttribute('data-copy') ?? ''
    void navigator.clipboard.writeText(value).then(() => {
      const labelKey = (btn.getAttribute('data-label-key') ||
        'mtaStsBuilder.result.copy') as MessageKey
      btn.textContent = t('mtaStsBuilder.result.copied')
      if (copyResetTimer) clearTimeout(copyResetTimer)
      copyResetTimer = setTimeout(() => {
        btn.textContent = t(labelKey)
      }, 1500)
    })
  })
}
