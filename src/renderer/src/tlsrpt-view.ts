import { t } from '../../shared/i18n'
import type { AnalyzeResult } from '../../shared/types'
import {
  btnCloseTlsRptDetail,
  btnTlsRptDetailClose,
  filterDomainEl,
  tlsRptBody,
  tlsRptDetailBody,
  tlsRptDetailDialog,
  tlsRptSummary
} from './dom'
import { escapeHtml, formatRange } from './format'
import { state } from './state'

export function renderTlsRpt(result: AnalyzeResult | null): void {
  const reports = result?.tlsRptReports ?? []
  const domainFilter = filterDomainEl.value.trim().toLowerCase()
  const policies = reports.flatMap((report, reportIndex) =>
    report.policies.flatMap((policy, policyIndex) =>
      !domainFilter || policy.policyDomain.trim().toLowerCase() === domainFilter
        ? [{ report, reportIndex, policy, policyIndex }]
        : []
    )
  )
  const successful = policies.reduce((sum, row) => sum + row.policy.successfulSessions, 0)
  const failed = policies.reduce((sum, row) => sum + row.policy.failedSessions, 0)
  tlsRptSummary.textContent = t('tlsRpt.summary', {
    reports: new Set(policies.map((row) => row.reportIndex)).size,
    successful,
    failed
  })

  const rows = policies.map(({ report, reportIndex, policy, policyIndex }) => {
    const reasons = new Map<string, number>()
    for (const detail of policy.failureDetails) {
      const name = detail.failureReasonCode || detail.resultType
      reasons.set(name, (reasons.get(name) ?? 0) + detail.failedSessionCount)
    }
    const reasonText = [...reasons.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${name} (${count})`)
      .join(', ')
    return `<tr
      data-report-index="${reportIndex}"
      data-policy-index="${policyIndex}"
      role="button"
      tabindex="0"
      aria-label="${escapeHtml(t('tlsRpt.openDetails'))}"
    >
      <td>${escapeHtml(formatRange(report.dateBegin, report.dateEnd))}</td>
      <td>${escapeHtml(report.orgName)}</td>
      <td>${escapeHtml(policy.policyDomain)}</td>
      <td>${escapeHtml(policy.policyType)}</td>
      <td class="pass">${policy.successfulSessions}</td>
      <td class="${policy.failedSessions ? 'fail' : ''}">${policy.failedSessions}</td>
      <td>${escapeHtml(reasonText || '—')}</td>
    </tr>`
  })
  tlsRptBody.innerHTML =
    rows.join('') || `<tr class="empty"><td colspan="7">${escapeHtml(t('tlsRpt.empty'))}</td></tr>`
}

export function openTlsRptDetails(reportIndex: number, policyIndex: number): void {
  const report = state.viewResult?.tlsRptReports[reportIndex]
  const policy = report?.policies[policyIndex]
  if (!report || !policy) return

  const field = (label: string, value: string | number | null | undefined): string =>
    `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value == null || value === '' ? '—' : String(value))}</dd>`
  const list = (values: string[]): string => values.map(escapeHtml).join('<br>') || '—'
  const failureDetails = policy.failureDetails.length
    ? policy.failureDetails
        .map(
          (detail) => `<section class="tlsrpt-failure-detail">
            <dl>
              ${field(t('tlsRpt.resultType'), detail.resultType)}
              ${field(t('tlsRpt.failedSessionCount'), detail.failedSessionCount)}
              ${field(t('tlsRpt.failureReasonCode'), detail.failureReasonCode)}
              ${field(t('tlsRpt.sendingMtaIp'), detail.sendingMtaIp)}
              ${field(t('tlsRpt.receivingMxHostname'), detail.receivingMxHostname)}
              ${field(t('tlsRpt.receivingIp'), detail.receivingIp)}
              ${field(t('tlsRpt.additionalInformation'), detail.additionalInformation)}
            </dl>
          </section>`
        )
        .join('')
    : `<p>${escapeHtml(t('tlsRpt.noFailureDetails'))}</p>`

  tlsRptDetailBody.innerHTML = `
    <section>
      <h3>${escapeHtml(t('tlsRpt.report'))}</h3>
      <dl>
        ${field(t('tlsRpt.organization'), report.orgName)}
        ${field(t('tlsRpt.reportId'), report.reportId)}
        ${field(t('tlsRpt.period'), formatRange(report.dateBegin, report.dateEnd))}
      </dl>
    </section>
    <section>
      <h3>${escapeHtml(t('tlsRpt.policyDetails'))}</h3>
      <dl>
        ${field(t('tlsRpt.domain'), policy.policyDomain)}
        ${field(t('tlsRpt.policyType'), policy.policyType)}
        <dt>${escapeHtml(t('tlsRpt.policyString'))}</dt><dd>${list(policy.policyString)}</dd>
        <dt>${escapeHtml(t('tlsRpt.mxHosts'))}</dt><dd>${list(policy.mxHosts)}</dd>
        ${field(t('tlsRpt.successfulSessions'), policy.successfulSessions)}
        ${field(t('tlsRpt.failedSessions'), policy.failedSessions)}
      </dl>
    </section>
    <section>
      <h3>${escapeHtml(t('tlsRpt.failureDetail'))}</h3>
      ${failureDetails}
    </section>`
  tlsRptDetailDialog.showModal()
}

export function openTlsRptDetailsFromRow(row: HTMLTableRowElement): void {
  const reportIndex = Number(row.dataset.reportIndex)
  const policyIndex = Number(row.dataset.policyIndex)
  if (Number.isInteger(reportIndex) && Number.isInteger(policyIndex)) {
    openTlsRptDetails(reportIndex, policyIndex)
  }
}

export function initTlsRptDetailEvents(): void {
  btnCloseTlsRptDetail.addEventListener('click', () => tlsRptDetailDialog.close())
  btnTlsRptDetailClose.addEventListener('click', () => tlsRptDetailDialog.close())
  tlsRptBody.addEventListener('click', (event) => {
    if (!(event.target instanceof Element)) return
    const row = event.target.closest<HTMLTableRowElement>('tr[data-report-index]')
    if (row) openTlsRptDetailsFromRow(row)
  })
  tlsRptBody.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return
    if (!(event.target instanceof Element)) return
    const row = event.target.closest<HTMLTableRowElement>('tr[data-report-index]')
    if (!row) return
    event.preventDefault()
    openTlsRptDetailsFromRow(row)
  })
}
