import { t, type AppLocale, type MessageKey } from './i18n'
import { monthLabel } from './report-period'
import type {
  AlignmentBreakdown,
  AnalyzeResult,
  DomainHealth,
  NamedBucket,
  ProblemSourceRow,
  VolumePoint
} from './types'

export interface ManagementReportInput {
  result: AnalyzeResult
  locale: AppLocale
  /** Covered month as `YYYY-MM`; falls back to the data range in the header. */
  month?: string
  /** Domain the data was filtered to; null means all domains. */
  domain?: string | null
  /** Account label shown in the header, e.g. the mailbox domain. */
  account?: string | null
  /** DNS traffic light per domain, when available. */
  domains?: DomainHealth[]
  generatedAt?: string
  appVersion?: string
}

/** A single management-level takeaway with the data that justifies it. */
export interface ReportFinding {
  key: MessageKey
  params?: Record<string, string | number>
  level: 'ok' | 'warn' | 'bad'
}

const COLORS = {
  pass: '#2f9e5f',
  fail: '#d0453b',
  other: '#8a94a6',
  grid: '#d7dce4',
  text: '#2b323d'
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function intl(locale: AppLocale): string {
  return locale === 'de' ? 'de-DE' : 'en-US'
}

function num(value: number, locale: AppLocale): string {
  return new Intl.NumberFormat(intl(locale)).format(value)
}

function pct(value: number, locale: AppLocale): string {
  return `${new Intl.NumberFormat(intl(locale), { maximumFractionDigits: 1 }).format(value)}%`
}

function day(iso: string | null, locale: AppLocale): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return new Intl.DateTimeFormat(intl(locale), { dateStyle: 'medium' }).format(date)
}

function rate(passing: number, total: number): number {
  if (total <= 0) return 0
  return Math.round((passing / total) * 1000) / 10
}

/** Donut with pass/fail/other shares; falls back to an empty ring without data. */
function donutSvg(title: string, data: AlignmentBreakdown, locale: AppLocale): string {
  const total = data.pass + data.fail + data.other
  const radius = 42
  const circumference = 2 * Math.PI * radius
  const segments: Array<{ value: number; color: string }> = [
    { value: data.pass, color: COLORS.pass },
    { value: data.fail, color: COLORS.fail },
    { value: data.other, color: COLORS.other }
  ]
  let offset = 0
  const arcs = segments
    .filter((s) => s.value > 0)
    .map((s) => {
      const length = (s.value / total) * circumference
      const arc = `<circle class="arc" r="${radius}" cx="60" cy="60" stroke="${s.color}"
        stroke-dasharray="${length.toFixed(2)} ${(circumference - length).toFixed(2)}"
        stroke-dashoffset="${(-offset).toFixed(2)}" />`
      offset += length
      return arc
    })
    .join('')
  const center = total > 0 ? pct(rate(data.pass, total), locale) : '—'
  return `<figure class="chart">
    <svg viewBox="0 0 120 120" role="img" aria-label="${escapeHtml(title)}">
      <circle r="${radius}" cx="60" cy="60" stroke="${COLORS.grid}" class="arc" />
      ${arcs}
      <text x="60" y="64" class="donut-value">${escapeHtml(center)}</text>
    </svg>
    <figcaption>
      <strong>${escapeHtml(title)}</strong>
      <span>${escapeHtml(t('pdf.passFail', { pass: num(data.pass, locale), fail: num(data.fail, locale) }, locale))}</span>
    </figcaption>
  </figure>`
}

/** Stacked daily volume (passing over failing) with a pass-rate line. */
function volumeSvg(points: VolumePoint[], locale: AppLocale): string {
  if (points.length === 0) return ''
  const width = 700
  const height = 180
  const padLeft = 44
  const padBottom = 26
  const padTop = 10
  const plotW = width - padLeft - 12
  const plotH = height - padBottom - padTop
  const max = Math.max(...points.map((p) => p.total), 1)
  const slot = plotW / points.length
  const barW = Math.max(1.5, Math.min(18, slot * 0.7))

  const bars = points
    .map((p, i) => {
      const x = padLeft + slot * i + (slot - barW) / 2
      const hPass = (p.passing / max) * plotH
      const hFail = (p.failing / max) * plotH
      const yFail = padTop + plotH - hFail
      const yPass = yFail - hPass
      return `<rect x="${x.toFixed(1)}" y="${yPass.toFixed(1)}" width="${barW.toFixed(1)}" height="${hPass.toFixed(1)}" fill="${COLORS.pass}" />
        <rect x="${x.toFixed(1)}" y="${yFail.toFixed(1)}" width="${barW.toFixed(1)}" height="${hFail.toFixed(1)}" fill="${COLORS.fail}" />`
    })
    .join('')

  const ticks = [0, 0.5, 1]
    .map((f) => {
      const y = padTop + plotH - f * plotH
      const label = num(Math.round(max * f), locale)
      return `<line x1="${padLeft}" y1="${y.toFixed(1)}" x2="${width - 12}" y2="${y.toFixed(1)}" stroke="${COLORS.grid}" stroke-width="0.7" />
        <text x="${padLeft - 6}" y="${(y + 3).toFixed(1)}" class="axis" text-anchor="end">${escapeHtml(label)}</text>`
    })
    .join('')

  const step = Math.ceil(points.length / 8)
  const xLabels = points
    .map((p, i) => {
      if (i % step !== 0) return ''
      const x = padLeft + slot * i + slot / 2
      const label = new Intl.DateTimeFormat(intl(locale), {
        day: '2-digit',
        month: '2-digit'
      }).format(new Date(p.date))
      return `<text x="${x.toFixed(1)}" y="${height - 8}" class="axis" text-anchor="middle">${escapeHtml(label)}</text>`
    })
    .join('')

  return `<svg class="volume" viewBox="0 0 ${width} ${height}" role="img"
    aria-label="${escapeHtml(t('pdf.volume', undefined, locale))}">
    ${ticks}${bars}${xLabels}
  </svg>`
}

function kpiTile(label: string, value: string, hint?: string): string {
  return `<div class="kpi">
    <span class="kpi-label">${escapeHtml(label)}</span>
    <strong class="kpi-value">${escapeHtml(value)}</strong>
    ${hint ? `<span class="kpi-hint">${escapeHtml(hint)}</span>` : ''}
  </div>`
}

function bucketRows(rows: NamedBucket[], locale: AppLocale, limit: number): string {
  return rows
    .slice(0, limit)
    .map(
      (r) => `<tr>
        <td>${escapeHtml(r.name || '—')}${r.provider ? `<span class="meta">${escapeHtml(r.provider)}</span>` : ''}</td>
        <td class="num">${escapeHtml(num(r.count, locale))}</td>
        <td class="num">${escapeHtml(num(r.failing, locale))}</td>
        <td class="num">${escapeHtml(pct(r.passRate, locale))}</td>
      </tr>`
    )
    .join('')
}

function problemRows(rows: ProblemSourceRow[], locale: AppLocale, limit: number): string {
  return rows
    .slice(0, limit)
    .map((r) => {
      const category = r.category
        ? t(`problems.cat.${r.category}` as MessageKey, undefined, locale)
        : '—'
      return `<tr>
        <td class="mono">${escapeHtml(r.sourceIp)}</td>
        <td>${escapeHtml(category)}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
        <td class="num">${escapeHtml(num(r.count, locale))}</td>
        <td class="num">${escapeHtml(num(r.spfFail, locale))} / ${escapeHtml(num(r.dkimFail, locale))}</td>
      </tr>`
    })
    .join('')
}

function domainRows(rows: DomainHealth[], locale: AppLocale): string {
  return rows
    .map(
      (d) => `<tr>
        <td>${escapeHtml(d.domain)}</td>
        <td><span class="pill ${d.status}">${escapeHtml(t(`pdf.status.${d.status}` as MessageKey, undefined, locale))}</span></td>
        <td>${escapeHtml(d.dmarcPolicy ? `p=${d.dmarcPolicy}` : '—')}</td>
        <td>${escapeHtml(boolLabel(d.spfOk, locale))}</td>
        <td>${escapeHtml(boolLabel(d.dkimOk, locale))}</td>
        <td class="num">${escapeHtml(num(d.total, locale))}</td>
        <td class="num">${escapeHtml(pct(d.passRate, locale))}</td>
      </tr>`
    )
    .join('')
}

function boolLabel(value: boolean | null, locale: AppLocale): string {
  if (value == null) return '—'
  return t(value ? 'pdf.yes' : 'pdf.no', undefined, locale)
}

/**
 * Management takeaways derived from the data alone, so the report also works
 * for the unattended monthly run where no DNS check has happened.
 */
export function buildFindings(input: {
  result: AnalyzeResult
  domains?: DomainHealth[]
}): ReportFinding[] {
  const { aggregate, dashboard, forensicReports } = input.result
  const findings: ReportFinding[] = []
  const passRate = aggregate.passRate

  if (aggregate.total === 0) {
    return [{ key: 'pdf.finding.noData', level: 'warn' }]
  }

  if (passRate >= 98)
    findings.push({ key: 'pdf.finding.passRateGood', params: { rate: passRate }, level: 'ok' })
  else if (passRate >= 95)
    findings.push({ key: 'pdf.finding.passRateFair', params: { rate: passRate }, level: 'warn' })
  else findings.push({ key: 'pdf.finding.passRateLow', params: { rate: passRate }, level: 'bad' })

  const spoof = dashboard.problemSources
    .filter((s) => s.category === 'unauthenticated')
    .reduce((sum, s) => sum + s.count, 0)
  if (spoof > 0) {
    findings.push({ key: 'pdf.finding.spoof', params: { count: spoof }, level: 'bad' })
  }

  const thirdParty = dashboard.problemSources.filter((s) => s.category === 'thirdParty')
  if (thirdParty.length > 0) {
    findings.push({
      key: 'pdf.finding.thirdParty',
      params: { count: thirdParty.length, ip: thirdParty[0].sourceIp },
      level: 'warn'
    })
  }

  const broken = dashboard.problemSources.filter((s) => s.category === 'broken')
  if (broken.length > 0) {
    findings.push({ key: 'pdf.finding.broken', params: { count: broken.length }, level: 'warn' })
  }

  const monitoring = (input.domains ?? []).filter((d) => d.dmarcPolicy === 'none')
  if (monitoring.length > 0) {
    findings.push({
      key: 'pdf.finding.policyNone',
      params: { domains: monitoring.map((d) => d.domain).join(', ') },
      level: 'warn'
    })
  }
  const enforcing = (input.domains ?? []).filter(
    (d) => d.dmarcPolicy === 'reject' || d.dmarcPolicy === 'quarantine'
  )
  if (enforcing.length > 0) {
    findings.push({
      key: 'pdf.finding.policyEnforced',
      params: { count: enforcing.length },
      level: 'ok'
    })
  }

  if (forensicReports.length > 0) {
    findings.push({
      key: 'pdf.finding.forensic',
      params: { count: forensicReports.length },
      level: 'warn'
    })
  }

  return findings
}

function findingList(findings: ReportFinding[], locale: AppLocale): string {
  return findings
    .map(
      (f) => `<li class="finding ${f.level}">
        <span class="dot"></span>${escapeHtml(t(f.key, f.params, locale))}
      </li>`
    )
    .join('')
}

/** Compact app mark — inlined so the PDF has no external files. */
const BRAND_MARK = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-label="DMARC Lighthouse">
  <defs>
    <linearGradient id="pdf-brand-bg" x1="80" y1="48" x2="432" y2="464" gradientUnits="userSpaceOnUse">
      <stop stop-color="#177089"/>
      <stop offset="1" stop-color="#0A3A4C"/>
    </linearGradient>
  </defs>
  <rect x="24" y="24" width="464" height="464" rx="92" fill="url(#pdf-brand-bg)"/>
  <rect x="96" y="148" width="320" height="200" rx="32" fill="#F4FAFB"/>
  <path fill="#083140" d="M96 180V176c0-16 12-28 28-28h264c16 0 28 12 28 28v4L278 292c-12 10-28 10-40 0L96 180z"/>
  <path fill="#F4FAFB" d="M112 176l132 104c8 6 20 6 28 0l132-104H112z"/>
  <path fill="#2BB4A3" d="M256 262c58 0 102-24 102-24v62c0 56-38 98-102 128-64-30-102-72-102-128v-62s44 24 102 24z"/>
  <path fill="#F4FAFB" d="M222 348l-28-28 22-22 28 28 66-66 22 22-88 88z"/>
</svg>`

const STYLES = `
  @page { size: A4; margin: 14mm 12mm 16mm; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font: 10pt/1.45 "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    color: ${COLORS.text};
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
  h1 { font-size: 19pt; margin: 0 0 2mm; }
  h2 { font-size: 12pt; margin: 7mm 0 2mm; padding-bottom: 1mm; border-bottom: 1px solid ${COLORS.grid}; }
  header.cover { border-bottom: 2px solid ${COLORS.text}; padding-bottom: 3mm; margin-bottom: 4mm; }
  .brand-row { display: flex; align-items: center; justify-content: space-between; gap: 6mm; margin-bottom: 3.5mm; }
  .brand-left { display: flex; align-items: center; gap: 3mm; min-width: 0; }
  .brand-mark { width: 11mm; height: 11mm; flex: 0 0 11mm; }
  .brand-mark svg { width: 11mm; height: 11mm; display: block; }
  .brand-name { font-size: 11.5pt; font-weight: 700; letter-spacing: .02em; color: #0a3a4c; line-height: 1.15; }
  .brand-tag { display: block; font-size: 7.5pt; font-weight: 500; color: #64708a; letter-spacing: .04em; }
  .brand-maker { text-align: right; font-size: 10pt; font-weight: 700; color: #177089; line-height: 1.2; }
  .brand-maker small { display: block; font-size: 7.5pt; font-weight: 500; color: #64708a; }
  .subtitle { font-size: 11pt; color: #4d566a; }
  .cover-meta { margin-top: 2mm; font-size: 9pt; color: #5b6474; display: flex; gap: 6mm; flex-wrap: wrap; }
  .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 3mm; }
  .kpi { border: 1px solid ${COLORS.grid}; border-radius: 2mm; padding: 2.5mm 3mm; }
  .kpi-label { display: block; font-size: 8pt; text-transform: uppercase; letter-spacing: .04em; color: #64708a; }
  .kpi-value { display: block; font-size: 16pt; line-height: 1.2; }
  .kpi-hint { font-size: 8pt; color: #6b7488; }
  .charts { display: grid; grid-template-columns: repeat(3, 1fr); gap: 4mm; align-items: start; }
  .chart svg { width: 100%; max-width: 34mm; height: auto; }
  .chart .arc { fill: none; stroke-width: 12; transform: rotate(-90deg); transform-origin: 60px 60px; }
  .donut-value { font-size: 15px; font-weight: 600; text-anchor: middle; fill: ${COLORS.text}; }
  figure.chart { margin: 0; text-align: center; }
  figcaption { font-size: 8.5pt; }
  figcaption strong { display: block; }
  figcaption span { color: #64708a; }
  svg.volume { width: 100%; height: auto; }
  .axis { font-size: 9px; fill: #64708a; }
  .legend { display: flex; gap: 4mm; font-size: 8.5pt; color: #5b6474; margin-top: 1mm; }
  .legend i { display: inline-block; width: 3mm; height: 3mm; border-radius: 0.5mm; margin-right: 1mm; vertical-align: -0.3mm; }
  table { width: 100%; border-collapse: collapse; font-size: 9pt; }
  th, td { text-align: left; padding: 1.4mm 2mm; border-bottom: 1px solid ${COLORS.grid}; vertical-align: top; }
  th { font-size: 8pt; text-transform: uppercase; letter-spacing: .03em; color: #64708a; }
  td.num, th.num { text-align: right; white-space: nowrap; }
  .mono { font-family: "Cascadia Mono", Consolas, monospace; font-size: 8.5pt; }
  .meta { display: block; font-size: 8pt; color: #6b7488; }
  ul.findings { list-style: none; margin: 0; padding: 0; }
  li.finding { position: relative; padding-left: 5mm; margin-bottom: 1.4mm; }
  li.finding .dot { position: absolute; left: 0; top: 1.4mm; width: 2.6mm; height: 2.6mm; border-radius: 50%; }
  li.ok .dot { background: ${COLORS.pass}; }
  li.warn .dot { background: #d9a222; }
  li.bad .dot { background: ${COLORS.fail}; }
  .pill { display: inline-block; padding: 0.2mm 1.6mm; border-radius: 1mm; font-size: 8pt; border: 1px solid ${COLORS.grid}; }
  .pill.ok { background: #e6f4ec; border-color: #b5dcc4; }
  .pill.warn { background: #fdf3dc; border-color: #ecd79a; }
  .pill.bad { background: #fbe6e4; border-color: #edb7b1; }
  section { break-inside: avoid; }
  footer { margin-top: 8mm; padding-top: 2mm; border-top: 1px solid ${COLORS.grid}; font-size: 8pt; color: #6b7488; }
  footer .maker { margin-top: 0.8mm; }
`

/** Self-contained HTML for the management report — no external assets. */
export function buildManagementReportHtml(input: ManagementReportInput): string {
  const { result, locale } = input
  const tr = (key: MessageKey, params?: Record<string, string | number>): string =>
    t(key, params, locale)
  const { aggregate, dashboard } = result
  const generatedAt = input.generatedAt ?? new Date().toISOString()
  const period = input.month
    ? monthLabel(input.month, locale)
    : `${day(aggregate.dateBegin, locale)} – ${day(aggregate.dateEnd, locale)}`
  const domainLabel = input.domain ?? tr('pdf.allDomains')
  const deliveredFails = dashboard.problemSources.reduce((sum, s) => sum + s.count, 0)
  const findings = buildFindings({ result, domains: input.domains })

  const meta = [
    tr('pdf.metaPeriod', { period }),
    tr('pdf.metaDomain', { domain: domainLabel }),
    ...(input.account ? [tr('pdf.metaAccount', { account: input.account })] : []),
    tr('pdf.metaGenerated', { date: day(generatedAt, locale) })
  ]

  const volume = volumeSvg(dashboard.volumeByDay, locale)
  const domainsTable =
    (input.domains ?? []).length > 0
      ? `<section>
          <h2>${escapeHtml(tr('pdf.domainsTitle'))}</h2>
          <table>
            <thead><tr>
              <th>${escapeHtml(tr('pdf.colDomain'))}</th>
              <th>${escapeHtml(tr('pdf.colStatus'))}</th>
              <th>DMARC</th><th>SPF</th><th>DKIM</th>
              <th class="num">${escapeHtml(tr('pdf.colMessages'))}</th>
              <th class="num">${escapeHtml(tr('pdf.colPassRate'))}</th>
            </tr></thead>
            <tbody>${domainRows(input.domains ?? [], locale)}</tbody>
          </table>
        </section>`
      : ''

  const problems =
    dashboard.problemSources.length > 0
      ? `<section>
          <h2>${escapeHtml(tr('pdf.problemsTitle'))}</h2>
          <p class="subtitle" style="font-size:9pt">${escapeHtml(tr('pdf.problemsHint'))}</p>
          <table>
            <thead><tr>
              <th>${escapeHtml(tr('pdf.colSource'))}</th>
              <th>${escapeHtml(tr('pdf.colCategory'))}</th>
              <th>${escapeHtml(tr('pdf.colHeaderFrom'))}</th>
              <th class="num">${escapeHtml(tr('pdf.colMessages'))}</th>
              <th class="num">${escapeHtml(tr('pdf.colSpfDkim'))}</th>
            </tr></thead>
            <tbody>${problemRows(dashboard.problemSources, locale, 10)}</tbody>
          </table>
        </section>`
      : ''

  return `<!DOCTYPE html>
<html lang="${locale}">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(tr('pdf.title'))} — ${escapeHtml(domainLabel)} — ${escapeHtml(period)}</title>
<style>${STYLES}</style>
</head>
<body>
<header class="cover">
  <div class="brand-row">
    <div class="brand-left">
      <div class="brand-mark">${BRAND_MARK}</div>
      <div>
        <div class="brand-name">DMARC Lighthouse</div>
        <span class="brand-tag">${escapeHtml(tr('pdf.brand.tag'))}</span>
      </div>
    </div>
    <div class="brand-maker">codemacher<small>${escapeHtml(tr('pdf.brand.makerLegal'))}</small></div>
  </div>
  <h1>${escapeHtml(tr('pdf.title'))}</h1>
  <div class="subtitle">${escapeHtml(tr('pdf.subtitle'))}</div>
  <div class="cover-meta">${meta.map((m) => `<span>${escapeHtml(m)}</span>`).join('')}</div>
</header>

<section>
  <h2>${escapeHtml(tr('pdf.summaryTitle'))}</h2>
  <div class="kpis">
    ${kpiTile(tr('pdf.kpiMessages'), num(aggregate.total, locale), tr('pdf.kpiReports', { count: num(aggregate.reportCount, locale) }))}
    ${kpiTile(tr('pdf.kpiPassRate'), pct(aggregate.passRate, locale), tr('pdf.kpiPassing', { count: num(aggregate.passing, locale) }))}
    ${kpiTile(tr('pdf.kpiFailing'), num(aggregate.failing, locale), tr('pdf.kpiDelivered', { count: num(deliveredFails, locale) }))}
    ${kpiTile(tr('pdf.kpiDomains'), num(aggregate.domains.length, locale), tr('pdf.kpiOrgs', { count: num(dashboard.byOrg.length, locale) }))}
  </div>
</section>

<section>
  <h2>${escapeHtml(tr('pdf.findingsTitle'))}</h2>
  <ul class="findings">${findingList(findings, locale)}</ul>
</section>

<section>
  <h2>${escapeHtml(tr('pdf.alignmentTitle'))}</h2>
  <div class="charts">
    ${donutSvg('DMARC', dashboard.dmarc, locale)}
    ${donutSvg('SPF', dashboard.spf, locale)}
    ${donutSvg('DKIM', dashboard.dkim, locale)}
  </div>
</section>

${
  volume
    ? `<section>
  <h2>${escapeHtml(tr('pdf.volumeTitle'))}</h2>
  ${volume}
  <div class="legend">
    <span><i style="background:${COLORS.pass}"></i>${escapeHtml(tr('pdf.legendPass'))}</span>
    <span><i style="background:${COLORS.fail}"></i>${escapeHtml(tr('pdf.legendFail'))}</span>
  </div>
</section>`
    : ''
}

${domainsTable}
${problems}

<section>
  <h2>${escapeHtml(tr('pdf.orgsTitle'))}</h2>
  <table>
    <thead><tr>
      <th>${escapeHtml(tr('pdf.colOrg'))}</th>
      <th class="num">${escapeHtml(tr('pdf.colMessages'))}</th>
      <th class="num">${escapeHtml(tr('pdf.colFailing'))}</th>
      <th class="num">${escapeHtml(tr('pdf.colPassRate'))}</th>
    </tr></thead>
    <tbody>${bucketRows(dashboard.byOrg, locale, 8)}</tbody>
  </table>
</section>

<section>
  <h2>${escapeHtml(tr('pdf.sourcesTitle'))}</h2>
  <table>
    <thead><tr>
      <th>${escapeHtml(tr('pdf.colSource'))}</th>
      <th class="num">${escapeHtml(tr('pdf.colMessages'))}</th>
      <th class="num">${escapeHtml(tr('pdf.colFailing'))}</th>
      <th class="num">${escapeHtml(tr('pdf.colPassRate'))}</th>
    </tr></thead>
    <tbody>${bucketRows(dashboard.bySourceIp, locale, 10)}</tbody>
  </table>
</section>

<footer>
  ${escapeHtml(tr('pdf.footer', { version: input.appVersion ?? '' }))}
  <div class="maker">${escapeHtml(tr('pdf.footerMaker'))}</div>
</footer>
</body>
</html>`
}
