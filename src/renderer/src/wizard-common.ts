import { normalizeDomain } from '../../shared/dmarc-builder'
import { t, type MessageKey } from '../../shared/i18n'
import { filterDomainEl } from './dom'
import { escapeHtml } from './format'

/** Suggest the active dashboard filter domain for any record wizard. */
export function suggestInitialWizardDomain(): string {
  const fromFilter = filterDomainEl.value.trim()
  return fromFilter ? normalizeDomain(fromFilter) : ''
}

/** Scroll the horizontal step indicator so the active step stays centered. */
export function centerActiveWizardStep(list: HTMLElement): void {
  const active = list.querySelector<HTMLElement>('li.active')
  if (!active) return
  const listRect = list.getBoundingClientRect()
  const activeRect = active.getBoundingClientRect()
  const left =
    list.scrollLeft + (activeRect.left - listRect.left) - (list.clientWidth - activeRect.width) / 2
  list.scrollTo({ left: Math.max(0, left), behavior: 'smooth' })
}

/** Synchronize step pills, panels, and back/next button labels for a wizard dialog. */
export function syncWizardStepDom<S extends string>(options: {
  stepsEl: HTMLElement
  panelSelector: string
  backBtn: HTMLButtonElement
  nextBtn: HTMLButtonElement
  step: S
  firstStep?: S
  resultStep?: S
  stepIndex: (step: S) => number
  finishKey: MessageKey
  nextKey: MessageKey
}): void {
  const {
    stepsEl,
    panelSelector,
    backBtn,
    nextBtn,
    step,
    firstStep = 'domain' as S,
    resultStep = 'result' as S,
    stepIndex,
    finishKey,
    nextKey
  } = options
  const idx = stepIndex(step)
  for (const li of stepsEl.querySelectorAll('li')) {
    const s = li.getAttribute('data-step') as S | null
    if (!s) continue
    const si = stepIndex(s)
    li.classList.toggle('active', s === step)
    li.classList.toggle('done', si >= 0 && si < idx)
  }
  centerActiveWizardStep(stepsEl)
  for (const panel of document.querySelectorAll<HTMLElement>(panelSelector)) {
    panel.classList.toggle('hidden', panel.getAttribute('data-step') !== step)
  }
  backBtn.disabled = step === firstStep
  nextBtn.textContent = step === resultStep ? t(finishKey) : t(nextKey)
}

/** Render a standardized copy button inside a wizard result card. */
export function wizardCopyButtonHtml(value: string, labelKey: MessageKey): string {
  return `<button type="button" class="btn secondary btn-copy" data-copy="${escapeHtml(value)}" data-label-key="${escapeHtml(labelKey)}">${escapeHtml(t(labelKey))}</button>`
}

/** Delegate `.btn-copy` clicks inside a wizard result container with temporary "Copied" feedback. */
export function bindWizardCopyButtons(
  container: HTMLElement,
  defaultLabelKey: MessageKey,
  copiedKey: MessageKey
): void {
  let copyResetTimer: ReturnType<typeof setTimeout> | null = null
  container.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null
    const btn = target?.closest?.('.btn-copy') as HTMLButtonElement | null
    if (!btn) return
    const value = btn.getAttribute('data-copy') ?? ''
    void navigator.clipboard.writeText(value).then(() => {
      const labelKey = (btn.getAttribute('data-label-key') || defaultLabelKey) as MessageKey
      btn.textContent = t(copiedKey)
      if (copyResetTimer) clearTimeout(copyResetTimer)
      copyResetTimer = setTimeout(() => {
        btn.textContent = t(labelKey)
      }, 1500)
    })
  })
}

/** Coalesce concurrent async calls for the same lookup key (e.g. domain DNS template loading). */
export function createInflightDeduper(): {
  run: (key: string, fn: () => Promise<void>) => Promise<void>
} {
  let inflight: Promise<void> | null = null
  let inflightKey = ''
  return {
    run(key: string, fn: () => Promise<void>): Promise<void> {
      if (inflight && inflightKey === key) return inflight
      inflightKey = key
      inflight = fn().finally(() => {
        if (inflightKey === key) inflight = null
      })
      return inflight
    }
  }
}
