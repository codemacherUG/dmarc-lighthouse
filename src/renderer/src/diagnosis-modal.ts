import { isHealthyDmarcOutcome } from '../../shared/analyze'
import { diagnoseSource, type FailureDiagnosis } from '../../shared/diagnosis'
import { t } from '../../shared/i18n'
import { isAuthorizedSender } from '../../shared/ipcidr'
import type { SerializedRecord } from '../../shared/types'
import { btnCloseDiagnosis, btnDiagnosisClose, diagnosisBody, diagnosisDialog } from './dom'
import { escapeHtml } from './format'
import { findSpfPrefixesForDomain } from './problem-source-state'
import { state } from './state'

/** Gather the raw (already delivered, non-passing) records for a problem-source IP group. */
function collectDiagnosisRecords(ips: string[]): {
  records: SerializedRecord[]
  policyDomain: string
} {
  const records: SerializedRecord[] = []
  const domainCounts = new Map<string, number>()
  for (const report of state.viewResult?.reports ?? []) {
    for (const rec of report.records) {
      if (!ips.includes(rec.sourceIp) || isHealthyDmarcOutcome(rec)) continue
      records.push(rec)
      domainCounts.set(report.domain, (domainCounts.get(report.domain) ?? 0) + rec.count)
    }
  }
  let policyDomain = ''
  let best = -1
  for (const [domain, count] of domainCounts) {
    if (count > best) {
      best = count
      policyDomain = domain
    }
  }
  return { records, policyDomain }
}

function mechanismLine(kind: 'spf' | 'dkim', facts: FailureDiagnosis['spf']): string {
  if (!facts.domain) return t(`diagnosis.${kind}.missing`)
  if (facts.raw == null) return t(`diagnosis.${kind}.unknown`, { domain: facts.domain })
  if (facts.raw === 'pass') {
    return t(facts.aligned ? `diagnosis.${kind}.passAligned` : `diagnosis.${kind}.passNotAligned`)
  }
  return t(`diagnosis.${kind}.fail`, { domain: facts.domain, result: facts.raw })
}

const DIAGNOSIS_VERDICT_BADGE: Record<FailureDiagnosis['verdict'], string> = {
  likelyLegit: 'badge',
  possiblyLegit: 'badge warn',
  suspicious: 'badge bad',
  forwarded: 'badge'
}

export function renderDiagnosisBody(ips: string[]): void {
  const { records, policyDomain } = collectDiagnosisRecords(ips)
  if (!records.length || !policyDomain) {
    diagnosisBody.innerHTML = `<p class="muted">${escapeHtml(t('diagnosis.empty'))}</p>`
    return
  }
  const meta = state.ipLabelCache.get(ips[0])
  const sender = meta?.provider ? { name: meta.provider, kind: meta.senderKind } : null
  const prefixes = findSpfPrefixesForDomain(state.spfPrefixesByDomain, policyDomain)
  const isOwn = ips.some((ip) => isAuthorizedSender(ip, prefixes))
  const diag = diagnoseSource(records, policyDomain, sender, isOwn)
  if (!diag) {
    diagnosisBody.innerHTML = `<p class="muted">${escapeHtml(t('diagnosis.empty'))}</p>`
    return
  }

  const senderLine = diag.senderName
    ? t('diagnosis.senderDetected', { name: diag.senderName })
    : diag.senderKind
      ? t('diagnosis.senderKindDetected', { kind: t(`sender.kind.${diag.senderKind}`) })
      : t('diagnosis.senderNone')

  diagnosisBody.innerHTML = `
    <p class="diagnosis-title">
      <span class="${DIAGNOSIS_VERDICT_BADGE[diag.verdict]}">${escapeHtml(t(`diagnosis.verdict.${diag.verdict}`))}</span>
    </p>
    <p class="hint">${escapeHtml(t(`diagnosis.verdictHint.${diag.verdict}`))}</p>
    <fieldset class="settings-group">
      <legend>${escapeHtml(t('diagnosis.section.sender'))}</legend>
      <p>${escapeHtml(senderLine)}</p>
    </fieldset>
    <fieldset class="settings-group">
      <legend>${escapeHtml(t('diagnosis.section.auth'))}</legend>
      <p>${escapeHtml(mechanismLine('spf', diag.spf))}</p>
      <p>${escapeHtml(mechanismLine('dkim', diag.dkim))}</p>
    </fieldset>
    <fieldset class="settings-group">
      <legend>${escapeHtml(t('diagnosis.section.recommendation'))}</legend>
      <p><strong>${escapeHtml(t(`diagnosis.action.${diag.action}`, { domain: diag.domain }))}</strong></p>
    </fieldset>
    <p class="hint">${escapeHtml(t('diagnosis.sampleCount', { count: diag.sampleCount, domain: diag.domain }))}</p>
  `
}

export function openDiagnosis(ips: string[]): void {
  if (!ips.length) return
  renderDiagnosisBody(ips)
  diagnosisDialog.showModal()
}

export function initDiagnosisModalEvents(): void {
  btnCloseDiagnosis?.addEventListener('click', () => diagnosisDialog.close())
  btnDiagnosisClose?.addEventListener('click', () => diagnosisDialog.close())
}
