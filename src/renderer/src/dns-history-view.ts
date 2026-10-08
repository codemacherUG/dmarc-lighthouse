import { t } from '../../shared/i18n'
import type { DnsHistoryResult } from '../../shared/types'
import { escapeHtml, formatDate } from './format'

export function renderDnsHistory(
  history: DnsHistoryResult,
  options: { changesOpen?: boolean } = {}
): string {
  if (history.snapshots.length === 0) return ''
  const latestDrift = history.drifts[0]
  const latestDriftCorrelation = latestDrift
    ? history.correlations.find((correlation) => correlation.driftId === latestDrift.id)
    : undefined
  const parts = [escapeHtml(t('dns.historySnapshots', { count: history.snapshots.length }))]
  if (latestDrift) {
    parts.push(
      escapeHtml(
        t('dns.historyLastDrift', {
          title: latestDrift.title,
          date: formatDate(latestDrift.checkedAt)
        })
      )
    )
  }
  if (latestDriftCorrelation) {
    parts.push(
      escapeHtml(
        t('dns.historyCorrelation', {
          changeDate: formatDate(latestDriftCorrelation.driftAt),
          reportDate: formatDate(latestDriftCorrelation.afterWindowBegin),
          before: latestDriftCorrelation.beforeFailRate.toFixed(1),
          after: latestDriftCorrelation.afterFailRate.toFixed(1)
        })
      )
    )
  }
  const driftHistory =
    history.drifts.length > 0
      ? `<details class="dns-history-details"${options.changesOpen ? ' open' : ''}><summary>${escapeHtml(
          t('dns.historyShowChanges', { count: history.drifts.length })
        )}</summary><ol class="dns-history-events">${history.drifts
          .map(
            (event) =>
              `<li><span class="dns-history-date">${escapeHtml(
                formatDate(event.checkedAt)
              )}</span><strong>${escapeHtml(event.title)}</strong><div>${escapeHtml(event.detail)}</div>${
                event.before !== null || event.after !== null
                  ? `<dl class="dns-history-values">${
                      event.before !== null
                        ? `<dt>${escapeHtml(t('dns.historyBefore'))}</dt><dd><pre>${escapeHtml(
                            event.before
                          )}</pre></dd>`
                        : ''
                    }${
                      event.after !== null
                        ? `<dt>${escapeHtml(t('dns.historyAfter'))}</dt><dd><pre>${escapeHtml(
                            event.after
                          )}</pre></dd>`
                        : ''
                    }</dl>`
                  : ''
              }</li>`
          )
          .join('')}</ol></details>`
      : ''
  return `<div class="dns-history"><strong>${escapeHtml(t('dns.historyTitle'))}</strong><ul>${parts
    .map((part) => `<li>${part}</li>`)
    .join('')}</ul>${driftHistory}</div>`
}
