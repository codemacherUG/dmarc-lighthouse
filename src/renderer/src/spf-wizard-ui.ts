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
  validateSpfRecordSyntax,
  type SpfAllQualifier,
  type SpfBuilderInput,
  type SpfBuilderStep
} from '../../shared/spf-builder'
import { t } from '../../shared/i18n'
import type { SpfExpandResult, SpfLookupTreeNode, SpfOptimizationHint } from '../../shared/types'
import {
  btnCloseSpfBuilder,
  btnSpfBuilder,
  btnSpfBuilderBack,
  btnSpfBuilderNext,
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
import { refreshDomainHealth } from './view'
import {
  bindWizardCopyButtons,
  suggestInitialWizardDomain,
  syncWizardStepDom,
  wizardCopyButtonHtml
} from './wizard-common'

let currentStep: SpfBuilderStep = 'domain'
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
  syncWizardStepDom({
    stepsEl: spfBuilderStepsEl,
    panelSelector: '.spf-builder-panel',
    backBtn: btnSpfBuilderBack,
    nextBtn: btnSpfBuilderNext,
    step,
    stepIndex: spfStepIndex,
    finishKey: 'spfBuilder.finish',
    nextKey: 'spfBuilder.next'
  })
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
  return wizardCopyButtonHtml(value, 'spfBuilder.result.copy')
}

function formatNodeLookups(count: number): string {
  if (count === 0) return t('spfBuilder.expand.treeNoLookup')
  if (count === 1) return t('spfBuilder.expand.treeLookupSingle')
  return t('spfBuilder.expand.treeLookups', { count })
}

function renderTreeNode(node: SpfLookupTreeNode, isRoot = false): string {
  const badges: string[] = []
  if (node.kind === 'invalid') {
    badges.push(
      `<span class="spf-tree-badge bad">${escapeHtml(t('spfBuilder.expand.treeInvalid'))}</span>`
    )
  } else if (!isRoot) {
    const lookupClass = node.totalLookups >= 5 ? 'bad' : node.totalLookups >= 1 ? 'info' : 'neutral'
    badges.push(
      `<span class="spf-tree-badge ${lookupClass}">${escapeHtml(formatNodeLookups(node.totalLookups))}</span>`
    )
  }
  if (node.duplicate && !node.cycle) {
    badges.push(
      `<span class="spf-tree-badge warn">${escapeHtml(t('spfBuilder.expand.treeDuplicate'))}</span>`
    )
  }
  if (node.cycle) {
    badges.push(
      `<span class="spf-tree-badge bad">${escapeHtml(t('spfBuilder.expand.treeCycle'))}</span>`
    )
  }
  if (node.empty && !node.error) {
    badges.push(
      `<span class="spf-tree-badge warn">${escapeHtml(t('spfBuilder.expand.treeEmpty'))}</span>`
    )
  }

  const recordSnippet =
    !isRoot && node.record
      ? `<div class="spf-tree-record mono">${escapeHtml(node.record)}</div>`
      : ''
  const errorSnippet = node.error
    ? `<div class="spf-tree-error">${escapeHtml(node.error)}</div>`
    : ''
  const leafCidrs =
    (node.kind === 'a' || node.kind === 'mx') && node.cidrs.length > 0
      ? `<div class="spf-tree-cidrs mono">${node.cidrs.map((c) => escapeHtml(c)).join(', ')}</div>`
      : ''

  const childrenHtml =
    node.children.length > 0
      ? `<ul class="spf-tree-children">${node.children.map((c) => renderTreeNode(c, false)).join('')}</ul>`
      : ''

  return `<li class="spf-tree-node spf-tree-kind-${escapeHtml(node.kind)}">
    <div class="spf-tree-row">
      <code class="spf-tree-term mono">${escapeHtml(node.term)}</code>
      <span class="spf-tree-badges">${badges.join('')}</span>
    </div>
    ${recordSnippet}
    ${leafCidrs}
    ${errorSnippet}
    ${childrenHtml}
  </li>`
}

function formatOptimizationHint(hint: SpfOptimizationHint): string {
  switch (hint.code) {
    case 'syntax-error':
      return t('spfBuilder.expand.hint.syntaxError', { subject: hint.subject ?? '' })
    case 'multiple-records':
      return t('spfBuilder.expand.hint.multipleRecords')
    case 'lookup-limit-exceeded':
      return t('spfBuilder.expand.hint.lookupLimitExceeded', { lookups: hint.lookups ?? 0 })
    case 'lookup-budget-high':
      return t('spfBuilder.expand.hint.lookupBudgetHigh', { lookups: hint.lookups ?? 0 })
    case 'duplicate-include':
      return t('spfBuilder.expand.hint.duplicateInclude', { subject: hint.subject ?? '' })
    case 'nested-duplicate-include':
      return t('spfBuilder.expand.hint.nestedDuplicateInclude', { subject: hint.subject ?? '' })
    case 'redundant-cidr':
      return t('spfBuilder.expand.hint.redundantCidr', {
        subject: hint.subject ?? '',
        related: hint.related ?? ''
      })
    case 'covered-by-include':
      return t('spfBuilder.expand.hint.coveredByInclude', {
        subject: hint.subject ?? '',
        related: hint.related ?? ''
      })
    case 'empty-mechanism':
      return t('spfBuilder.expand.hint.emptyMechanism', { subject: hint.subject ?? '' })
    case 'deprecated-ptr':
      return t('spfBuilder.expand.hint.deprecatedPtr', { subject: hint.subject ?? '' })
    case 'all-pass':
      return t('spfBuilder.expand.hint.allPass', { subject: hint.subject ?? '+all' })
    case 'all-softfail':
      return t('spfBuilder.expand.hint.allSoftfail', { subject: hint.subject ?? '~all' })
  }
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

  const budgetPct = Math.min(100, Math.round((result.lookups / 10) * 100))
  const budgetTone = result.lookups > 10 ? 'bad' : result.lookups >= 8 ? 'warn' : 'ok'

  const treeHtml =
    result.tree && result.tree.children.length > 0
      ? `<div class="spf-tree-section">
          <span class="builder-result-label">${escapeHtml(t('spfBuilder.expand.treeTitle'))}</span>
          <ul class="spf-tree-root">${renderTreeNode(result.tree, true)}</ul>
        </div>`
      : ''

  const hints = result.hints ?? []
  const optimizerHtml = `<div class="spf-optimizer-section">
    <span class="builder-result-label">${escapeHtml(t('spfBuilder.expand.optimizerTitle'))}</span>
    ${
      hints.length === 0
        ? `<p class="spf-optimizer-clean">${escapeHtml(t('spfBuilder.expand.optimizerClean'))}</p>`
        : `<ul class="spf-optimizer-list">${hints
            .map(
              (h) =>
                `<li class="spf-optimizer-item ${escapeHtml(h.severity)}">${escapeHtml(formatOptimizationHint(h))}</li>`
            )
            .join('')}</ul>`
    }
  </div>`

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
      <div class="spf-lookup-budget">
        <div class="spf-lookup-budget-head">
          <span class="builder-result-label">${escapeHtml(t('spfBuilder.expand.treeTitle'))}</span>
          <span class="spf-lookup-budget-count ${budgetTone}">${escapeHtml(
            t('spfBuilder.expand.lookups', { count: String(result.lookups) })
          )}</span>
        </div>
        <div class="spf-lookup-meter" role="progressbar" aria-valuemin="0" aria-valuemax="10" aria-valuenow="${result.lookups}">
          <div class="spf-lookup-meter-fill ${budgetTone}" style="width: ${budgetPct}%"></div>
        </div>
      </div>
      ${treeHtml}
      ${optimizerHtml}
      <div class="builder-result-field spf-cidrs-section">
        <span class="builder-result-label">${escapeHtml(
          t('spfBuilder.expand.title', { count: result.cidrs.length })
        )}</span>
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
    const liveSyntaxErrors = validateSpfRecordSyntax(liveDnsValue)
    const liveErrorHtml = liveSyntaxErrors.length
      ? `<p class="builder-status error">${escapeHtml(
          t('dns.spfSyntaxError', { tokens: liveSyntaxErrors.join(', ') })
        )}</p>`
      : ''
    spfBuilderLiveEl.innerHTML = `<div class="builder-live-card">
      <span class="builder-result-label">${escapeHtml(t('spfBuilder.result.liveTitle'))}</span>
      <code class="mono">${escapeHtml(liveDnsValue)}</code>
      ${liveErrorHtml}
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
    void refreshDomainHealth(state.fullResult, { force: true })
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

export function openSpfBuilder(): void {
  fillForm({ ...DEFAULT_SPF_BUILDER_INPUT })
  const domain = suggestInitialWizardDomain()
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

  bindWizardCopyButtons(spfBuilderResultEl, 'spfBuilder.result.copy', 'spfBuilder.result.copied')
}
