import {
  BUILDER_STEPS,
  buildDmarcRecord,
  DEFAULT_BUILDER_INPUT,
  defaultDmarcMailbox,
  isValidDomain,
  normalizeDomain,
  normalizeFo,
  normalizePct,
  normalizePolicy,
  parseDmarcRecord,
  stepIndex,
  type DmarcBuilderInput,
  type DmarcBuilderStep,
  type FailureOption,
  type SubdomainPolicyOption
} from '../../shared/dmarc-builder'
import { t, type MessageKey } from '../../shared/i18n'
import {
  builderDialog,
  builderDomainEl,
  builderDomainStatusEl,
  builderFooterHintEl,
  builderLiveEl,
  builderPctEl,
  builderPolicyEl,
  builderResultEl,
  builderRuaEl,
  builderRufEl,
  builderSpEl,
  builderStepsEl,
  builderAdkimEl,
  builderAspfEl,
  btnBuilder,
  btnBuilderBack,
  btnBuilderLoadDns,
  btnBuilderNext,
  btnCloseBuilder,
  dnsDomainEl,
  filterDomainEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

let currentStep: DmarcBuilderStep = 'domain'
let copyResetTimer: ReturnType<typeof setTimeout> | null = null
let liveDnsValue: string | null = null

function readFo(): FailureOption[] {
  const boxes = document.querySelectorAll<HTMLInputElement>('input[name="builder-fo"]:checked')
  return normalizeFo([...boxes].map((b) => b.value))
}

function setFo(values: FailureOption[]): void {
  const selected = new Set(normalizeFo(values))
  for (const box of document.querySelectorAll<HTMLInputElement>('input[name="builder-fo"]')) {
    box.checked = selected.has(box.value as FailureOption)
  }
}

function readInput(): DmarcBuilderInput {
  const sp = builderSpEl.value as SubdomainPolicyOption
  return {
    domain: normalizeDomain(builderDomainEl.value),
    policy: normalizePolicy(builderPolicyEl.value),
    subdomainPolicy: sp === 'same' ? 'same' : normalizePolicy(sp),
    pct: normalizePct(builderPctEl.value),
    rua: builderRuaEl.value.trim(),
    ruf: builderRufEl.value.trim(),
    fo: readFo(),
    adkim: builderAdkimEl.value === 's' ? 's' : 'r',
    aspf: builderAspfEl.value === 's' ? 's' : 'r'
  }
}

function fillForm(input: Partial<DmarcBuilderInput>): void {
  if (input.domain != null) builderDomainEl.value = input.domain
  if (input.policy != null) builderPolicyEl.value = input.policy
  if (input.subdomainPolicy != null) builderSpEl.value = input.subdomainPolicy
  if (input.pct != null) builderPctEl.value = String(input.pct)
  if (input.rua != null) builderRuaEl.value = input.rua
  if (input.ruf != null) builderRufEl.value = input.ruf
  if (input.fo != null) setFo(input.fo)
  if (input.adkim != null) builderAdkimEl.value = input.adkim
  if (input.aspf != null) builderAspfEl.value = input.aspf
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

function showStep(step: DmarcBuilderStep): void {
  currentStep = step
  const idx = stepIndex(step)
  for (const li of builderStepsEl.querySelectorAll('li')) {
    const s = li.getAttribute('data-step') as DmarcBuilderStep | null
    if (!s) continue
    const si = stepIndex(s)
    li.classList.toggle('active', s === step)
    li.classList.toggle('done', si >= 0 && si < idx)
  }
  centerActiveStep(builderStepsEl)
  for (const panel of document.querySelectorAll<HTMLElement>('.builder-panel')) {
    panel.classList.toggle('hidden', panel.getAttribute('data-step') !== step)
  }
  btnBuilderBack.disabled = step === 'domain'
  btnBuilderNext.textContent = step === 'result' ? t('builder.finish') : t('builder.next')
  const input = readInput()
  builderFooterHintEl.textContent = input.domain || ''
  if (step === 'result') renderResult()
}

function validateCurrentStep(): boolean {
  const input = readInput()
  if (currentStep === 'domain' && !isValidDomain(input.domain)) {
    builderDomainStatusEl.textContent = t('builder.error.domain')
    builderDomainStatusEl.className = 'builder-status error'
    return false
  }
  if (currentStep === 'reporting' && !input.rua.trim()) {
    builderFooterHintEl.textContent = t('builder.error.rua')
    return false
  }
  builderDomainStatusEl.classList.remove('error')
  return true
}

function copyButton(value: string): string {
  return `<button type="button" class="btn secondary btn-copy" data-copy="${escapeHtml(value)}" data-label-key="builder.result.copy">${escapeHtml(t('builder.result.copy'))}</button>`
}

function renderResult(): void {
  const input = readInput()
  const record = buildDmarcRecord(input)

  builderResultEl.innerHTML = `
    <article class="builder-result-card">
      <div class="builder-result-top">
        <div class="builder-result-field">
          <span class="builder-result-label">${escapeHtml(t('builder.result.host'))}</span>
          <div class="builder-result-row">
            <code class="mono">${escapeHtml(record.host)}</code>
            ${copyButton(record.host)}
          </div>
        </div>
        <div class="builder-result-field builder-result-type">
          <span class="builder-result-label">${escapeHtml(t('builder.result.type'))}</span>
          <code class="mono">${escapeHtml(record.type)}</code>
        </div>
      </div>
      <div class="builder-result-field">
        <span class="builder-result-label">${escapeHtml(t('builder.result.value'))}</span>
        <div class="builder-result-value">
          <code class="mono">${escapeHtml(record.value)}</code>
          ${copyButton(record.value)}
        </div>
      </div>
      <div class="builder-result-tags">
        <span class="builder-result-label">${escapeHtml(t('builder.result.tags'))}</span>
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
    builderLiveEl.textContent = ''
    return
  }
  const same = liveDnsValue.replace(/\s+/g, '') === record.value.replace(/\s+/g, '')
  builderLiveEl.innerHTML = `<div class="builder-live-card">
    <span class="builder-result-label">${escapeHtml(t('builder.result.liveTitle'))}</span>
    <code class="mono">${escapeHtml(liveDnsValue)}</code>
    <p class="hint">${escapeHtml(same ? t('builder.result.liveSame') : t('builder.result.liveDifferent'))}</p>
  </div>`
}

function ensureDefaultMailboxes(domain: string): void {
  const mailbox = defaultDmarcMailbox(domain)
  if (!mailbox) return
  if (!builderRuaEl.value.trim()) builderRuaEl.value = mailbox
  if (!builderRufEl.value.trim()) builderRufEl.value = mailbox
}

async function loadDnsTemplate(): Promise<void> {
  const domain = normalizeDomain(builderDomainEl.value)
  if (!isValidDomain(domain)) {
    builderDomainStatusEl.textContent = t('builder.error.domain')
    builderDomainStatusEl.className = 'builder-status error'
    return
  }
  builderDomainStatusEl.textContent = t('builder.domain.loading', { domain })
  builderDomainStatusEl.className = 'builder-status'
  try {
    const result = await window.api.checkDns(domain)
    builderDomainEl.value = result.domain
    ensureDefaultMailboxes(result.domain)
    const existing =
      result.dmarc.records.find((r) => /v\s*=\s*DMARC1/i.test(r)) ?? result.dmarc.records[0] ?? null
    liveDnsValue = existing
    if (existing) {
      fillForm({ domain: result.domain, ...parseDmarcRecord(existing) })
      builderDomainStatusEl.textContent = t('builder.domain.loaded')
      builderDomainStatusEl.className = 'builder-status ok'
    } else {
      liveDnsValue = null
      builderDomainStatusEl.textContent = t('builder.domain.missing')
      builderDomainStatusEl.className = 'builder-status'
    }
  } catch (err) {
    liveDnsValue = null
    builderDomainStatusEl.textContent = t('builder.domain.error', {
      message: err instanceof Error ? err.message : String(err)
    })
    builderDomainStatusEl.className = 'builder-status error'
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

export function openBuilder(): void {
  fillForm({ ...DEFAULT_BUILDER_INPUT })
  const domain = suggestInitialDomain()
  if (domain) {
    builderDomainEl.value = domain
    ensureDefaultMailboxes(domain)
  }
  liveDnsValue = null
  builderDomainStatusEl.textContent = ''
  builderDomainStatusEl.className = 'builder-status muted'
  builderLiveEl.textContent = ''
  showStep('domain')
  builderDialog.showModal()
  builderDomainEl.focus()
}

export function refreshBuilderLocale(): void {
  if (!builderDialog.open) return
  showStep(currentStep)
}

export function initWizardUi(): void {
  btnBuilder.addEventListener('click', () => openBuilder())
  btnCloseBuilder.addEventListener('click', () => builderDialog.close())

  btnBuilderBack.addEventListener('click', () => {
    const idx = stepIndex(currentStep)
    if (idx > 0) showStep(BUILDER_STEPS[idx - 1])
  })

  btnBuilderNext.addEventListener('click', () => {
    if (currentStep === 'result') {
      builderDialog.close()
      return
    }
    if (!validateCurrentStep()) return
    if (currentStep === 'domain') {
      const domain = normalizeDomain(builderDomainEl.value)
      builderDomainEl.value = domain
      ensureDefaultMailboxes(domain)
    }
    const idx = stepIndex(currentStep)
    showStep(BUILDER_STEPS[idx + 1])
  })

  btnBuilderLoadDns.addEventListener('click', () => {
    void loadDnsTemplate()
  })

  builderDomainEl.addEventListener('change', () => {
    const domain = normalizeDomain(builderDomainEl.value)
    if (domain) ensureDefaultMailboxes(domain)
  })

  builderResultEl.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null
    const btn = target?.closest?.('.btn-copy') as HTMLButtonElement | null
    if (!btn) return
    const value = btn.getAttribute('data-copy') ?? ''
    void navigator.clipboard.writeText(value).then(() => {
      const labelKey = (btn.getAttribute('data-label-key') ||
        'builder.result.copy') as MessageKey
      btn.textContent = t('builder.result.copied')
      if (copyResetTimer) clearTimeout(copyResetTimer)
      copyResetTimer = setTimeout(() => {
        btn.textContent = t(labelKey)
      }, 1500)
    })
  })
}
