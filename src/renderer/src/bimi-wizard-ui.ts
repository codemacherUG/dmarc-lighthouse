import {
  BIMI_BUILDER_STEPS,
  DEFAULT_BIMI_BUILDER_INPUT,
  DEFAULT_BIMI_SELECTOR,
  bimiDmarcPrereq,
  bimiRecordsEquivalent,
  bimiStepIndex,
  buildBimiRecord,
  isValidBimiSelector,
  isValidDomain,
  normalizeBimiSelector,
  normalizeDomain,
  parseBimiBuilderRecord,
  parseBimiRecord,
  validateBimiBuilderStep,
  type BimiBuilderInput,
  type BimiBuilderStep
} from '../../shared/bimi-builder'
import { t, type MessageKey } from '../../shared/i18n'
import {
  bimiBuilderAuthorityEl,
  bimiBuilderDialog,
  bimiBuilderDomainEl,
  bimiBuilderDomainStatusEl,
  bimiBuilderFooterHintEl,
  bimiBuilderLiveEl,
  bimiBuilderLocationEl,
  bimiBuilderPreviewEl,
  bimiBuilderResultEl,
  bimiBuilderSelectorEl,
  bimiBuilderStepsEl,
  btnBimiBuilder,
  btnBimiBuilderBack,
  btnBimiBuilderNext,
  btnCloseBimiBuilder,
  dnsDomainEl,
  filterDomainEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

let currentStep: BimiBuilderStep = 'domain'
let copyResetTimer: ReturnType<typeof setTimeout> | null = null
let liveDnsValue: string | null = null
let dmarcHintKey: MessageKey | null = null
let dmarcHintPolicy = ''
let dmarcHintPct = ''
let loadGen = 0
let appliedKey = ''
let inflight: Promise<void> | null = null
let inflightKey = ''

function readInput(): BimiBuilderInput {
  return {
    domain: normalizeDomain(bimiBuilderDomainEl.value),
    selector: normalizeBimiSelector(bimiBuilderSelectorEl.value),
    location: bimiBuilderLocationEl.value.trim(),
    authority: bimiBuilderAuthorityEl.value.trim()
  }
}

function fillForm(input: Partial<BimiBuilderInput>): void {
  if (input.domain != null) bimiBuilderDomainEl.value = input.domain
  if (input.selector != null) bimiBuilderSelectorEl.value = input.selector
  if (input.location != null) bimiBuilderLocationEl.value = input.location
  if (input.authority != null) bimiBuilderAuthorityEl.value = input.authority
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

function showStep(step: BimiBuilderStep): void {
  currentStep = step
  const idx = bimiStepIndex(step)
  for (const li of bimiBuilderStepsEl.querySelectorAll('li')) {
    const s = li.getAttribute('data-step') as BimiBuilderStep | null
    if (!s) continue
    const si = bimiStepIndex(s)
    li.classList.toggle('active', s === step)
    li.classList.toggle('done', si >= 0 && si < idx)
  }
  centerActiveStep(bimiBuilderStepsEl)
  for (const panel of document.querySelectorAll<HTMLElement>('.bimi-builder-panel')) {
    panel.classList.toggle('hidden', panel.getAttribute('data-step') !== step)
  }
  btnBimiBuilderBack.disabled = step === 'domain'
  btnBimiBuilderNext.textContent =
    step === 'result' ? t('bimiBuilder.finish') : t('bimiBuilder.next')
  const input = readInput()
  bimiBuilderFooterHintEl.textContent = input.domain || ''
  if (step === 'domain') renderDomainPreview()
  if (step === 'result') renderResult()
}

function validateCurrentStep(): boolean {
  const input = readInput()
  const error = validateBimiBuilderStep(currentStep, input)
  if (!error) {
    bimiBuilderDomainStatusEl.classList.remove('error')
    return true
  }
  const message = t(error as MessageKey)
  if (currentStep === 'domain') {
    bimiBuilderDomainStatusEl.textContent = message
    bimiBuilderDomainStatusEl.className = 'builder-status error'
  } else {
    bimiBuilderFooterHintEl.textContent = message
  }
  return false
}

function copyButton(value: string): string {
  return `<button type="button" class="btn secondary btn-copy" data-copy="${escapeHtml(value)}" data-label-key="bimiBuilder.result.copy">${escapeHtml(t('bimiBuilder.result.copy'))}</button>`
}

function dmarcHintHtml(): string {
  if (!dmarcHintKey) return ''
  return `<p class="hint">${escapeHtml(
    t(dmarcHintKey, { policy: dmarcHintPolicy, pct: dmarcHintPct })
  )}</p>`
}

function renderResult(): void {
  const input = readInput()
  const record = buildBimiRecord(input)

  bimiBuilderResultEl.innerHTML = `
    <article class="builder-result-card">
      <div class="builder-result-top">
        <div class="builder-result-field">
          <span class="builder-result-label">${escapeHtml(t('bimiBuilder.result.host'))}</span>
          <div class="builder-result-row">
            <code class="mono">${escapeHtml(record.host)}</code>
            ${copyButton(record.host)}
          </div>
        </div>
        <div class="builder-result-field builder-result-type">
          <span class="builder-result-label">${escapeHtml(t('bimiBuilder.result.type'))}</span>
          <code class="mono">${escapeHtml(record.type)}</code>
        </div>
      </div>
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('bimiBuilder.result.value'))}</span>
        <div class="builder-result-value">
          <code class="mono">${escapeHtml(record.value)}</code>
          ${copyButton(record.value)}
        </div>
      </div>
      <div class="builder-result-tags">
        <span class="builder-result-label">${escapeHtml(t('bimiBuilder.result.tags'))}</span>
        <div class="builder-tag-list">
          ${record.tags
            .map(
              (tag) =>
                `<span class="builder-tag mono">${escapeHtml(tag.key)}=${escapeHtml(tag.value)}</span>`
            )
            .join('')}
        </div>
      </div>
      ${dmarcHintHtml()}
      ${input.authority ? '' : `<p class="hint">${escapeHtml(t('bimiBuilder.result.vmcHint'))}</p>`}
    </article>`

  if (!liveDnsValue) {
    bimiBuilderLiveEl.innerHTML = `<p class="hint">${escapeHtml(t('bimiBuilder.result.liveMissing'))}</p>`
    return
  }
  const same = bimiRecordsEquivalent(liveDnsValue, record.value)
  bimiBuilderLiveEl.innerHTML = `<div class="builder-live-card">
    <span class="builder-result-label">${escapeHtml(t('bimiBuilder.result.liveTitle'))}</span>
    <code class="mono">${escapeHtml(liveDnsValue)}</code>
    <p class="hint">${escapeHtml(same ? t('bimiBuilder.result.liveSame') : t('bimiBuilder.result.liveDifferent'))}</p>
  </div>`
}

function rememberDmarcPrereq(policy: string | null, records: string[]): boolean {
  const prereq = bimiDmarcPrereq(policy, records)
  dmarcHintPolicy = prereq.policy ?? ''
  dmarcHintPct = prereq.pct != null ? String(prereq.pct) : ''
  if (prereq.reason === 'ok') {
    dmarcHintKey = 'bimiBuilder.domain.dmarcOk'
    return true
  }
  if (prereq.reason === 'missing') dmarcHintKey = 'bimiBuilder.domain.dmarcMissing'
  else if (prereq.reason === 'pct') dmarcHintKey = 'bimiBuilder.domain.dmarcPct'
  else dmarcHintKey = 'bimiBuilder.domain.dmarcWeak'
  return false
}

function lookupKey(domain: string, selector: string): string {
  return `${domain}|${selector}`
}

function applyBimiTemplate(domain: string, selector: string, record: string | null): void {
  const parsed = record ? parseBimiBuilderRecord(record) : {}
  fillForm({
    domain,
    selector,
    location: parsed.location ?? '',
    authority: parsed.authority ?? ''
  })
}

function renderDomainPreview(): void {
  if (!liveDnsValue) {
    bimiBuilderPreviewEl.innerHTML = ''
    return
  }
  bimiBuilderPreviewEl.innerHTML = `<div class="builder-live-card">
    <span class="builder-result-label">${escapeHtml(t('bimiBuilder.result.liveTitle'))}</span>
    <code class="mono">${escapeHtml(liveDnsValue)}</code>
  </div>`
}

async function loadDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(bimiBuilderDomainEl.value)
  const selector = normalizeBimiSelector(bimiBuilderSelectorEl.value || DEFAULT_BIMI_SELECTOR)
  if (!isValidDomain(domain)) return
  const key = lookupKey(domain, selector)
  if (appliedKey === key) return

  const gen = ++loadGen
  bimiBuilderDomainEl.value = domain
  bimiBuilderSelectorEl.value = selector
  bimiBuilderDomainStatusEl.textContent = t('bimiBuilder.domain.loading', { domain })
  bimiBuilderDomainStatusEl.className = 'builder-status'
  dmarcHintKey = null
  try {
    const [dns, bimi] = await Promise.all([
      window.api.checkDns(domain),
      window.api.checkBimi(domain, selector)
    ])
    if (gen !== loadGen) return
    bimiBuilderDomainEl.value = dns.domain
    const dmarcOk = rememberDmarcPrereq(dns.dmarc.policy, dns.dmarc.records)
    const existing = bimi.records.find((r) => parseBimiRecord(r).found) ?? bimi.records[0] ?? null
    liveDnsValue = bimi.found ? existing : null
    appliedKey = lookupKey(dns.domain, selector)
    applyBimiTemplate(dns.domain, selector, liveDnsValue)
    const dmarcNote = t(dmarcHintKey ?? 'bimiBuilder.domain.dmarcMissing', {
      policy: dmarcHintPolicy,
      pct: dmarcHintPct
    })
    if (liveDnsValue) {
      bimiBuilderDomainStatusEl.textContent = `${t('bimiBuilder.domain.loaded')} ${dmarcNote}`
      bimiBuilderDomainStatusEl.className = dmarcOk ? 'builder-status ok' : 'builder-status warn'
    } else {
      bimiBuilderDomainStatusEl.textContent = `${t('bimiBuilder.domain.missing')} ${dmarcNote}`
      bimiBuilderDomainStatusEl.className = dmarcOk ? 'builder-status' : 'builder-status warn'
    }
    renderDomainPreview()
  } catch (err) {
    if (gen !== loadGen) return
    liveDnsValue = null
    appliedKey = ''
    dmarcHintKey = null
    bimiBuilderPreviewEl.innerHTML = ''
    bimiBuilderDomainStatusEl.textContent = t('bimiBuilder.domain.error', {
      message: err instanceof Error ? err.message : String(err)
    })
    bimiBuilderDomainStatusEl.className = 'builder-status error'
  }
}

function requestDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(bimiBuilderDomainEl.value)
  const selector = normalizeBimiSelector(bimiBuilderSelectorEl.value || DEFAULT_BIMI_SELECTOR)
  const key = lookupKey(domain, selector)
  if (inflight && inflightKey === key) return inflight
  inflightKey = key
  inflight = loadDnsTemplate().finally(() => {
    if (inflightKey === key) inflight = null
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

export function openBimiBuilder(): void {
  fillForm({ ...DEFAULT_BIMI_BUILDER_INPUT })
  const domain = suggestInitialDomain()
  if (domain) bimiBuilderDomainEl.value = domain
  liveDnsValue = null
  appliedKey = ''
  loadGen += 1
  dmarcHintKey = null
  bimiBuilderDomainStatusEl.textContent = ''
  bimiBuilderDomainStatusEl.className = 'builder-status muted'
  bimiBuilderPreviewEl.innerHTML = ''
  bimiBuilderLiveEl.textContent = ''
  showStep('domain')
  bimiBuilderDialog.showModal()
  bimiBuilderDomainEl.focus()
  if (isValidDomain(domain)) void requestDnsTemplate()
}

export function refreshBimiBuilderLocale(): void {
  if (!bimiBuilderDialog.open) return
  showStep(currentStep)
}

export function initBimiWizardUi(): void {
  btnBimiBuilder.addEventListener('click', () => openBimiBuilder())
  btnCloseBimiBuilder.addEventListener('click', () => bimiBuilderDialog.close())

  btnBimiBuilderBack.addEventListener('click', () => {
    const idx = bimiStepIndex(currentStep)
    if (idx > 0) showStep(BIMI_BUILDER_STEPS[idx - 1])
  })

  btnBimiBuilderNext.addEventListener('click', () => {
    void (async () => {
      if (currentStep === 'result') {
        bimiBuilderDialog.close()
        return
      }
      if (!validateCurrentStep()) return
      btnBimiBuilderNext.disabled = true
      try {
        if (currentStep === 'domain') {
          await requestDnsTemplate()
        } else if (currentStep === 'logo') {
          const key = lookupKey(
            normalizeDomain(bimiBuilderDomainEl.value),
            normalizeBimiSelector(bimiBuilderSelectorEl.value)
          )
          if (appliedKey && appliedKey !== key) await requestDnsTemplate()
        }
      } finally {
        btnBimiBuilderNext.disabled = false
      }
      const idx = bimiStepIndex(currentStep)
      showStep(BIMI_BUILDER_STEPS[idx + 1])
    })()
  })

  bimiBuilderDomainEl.addEventListener('change', () => {
    const domain = normalizeDomain(bimiBuilderDomainEl.value)
    bimiBuilderDomainEl.value = domain
    appliedKey = ''
    if (isValidDomain(domain)) void requestDnsTemplate()
  })

  bimiBuilderSelectorEl.addEventListener('change', () => {
    const selector = normalizeBimiSelector(bimiBuilderSelectorEl.value)
    bimiBuilderSelectorEl.value = selector
    appliedKey = ''
    if (
      isValidDomain(normalizeDomain(bimiBuilderDomainEl.value)) &&
      isValidBimiSelector(selector)
    ) {
      void requestDnsTemplate()
    }
  })

  bimiBuilderResultEl.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null
    const btn = target?.closest?.('.btn-copy') as HTMLButtonElement | null
    if (!btn) return
    const value = btn.getAttribute('data-copy') ?? ''
    void navigator.clipboard.writeText(value).then(() => {
      const labelKey = (btn.getAttribute('data-label-key') ||
        'bimiBuilder.result.copy') as MessageKey
      btn.textContent = t('bimiBuilder.result.copied')
      if (copyResetTimer) clearTimeout(copyResetTimer)
      copyResetTimer = setTimeout(() => {
        btn.textContent = t(labelKey)
      }, 1500)
    })
  })
}
