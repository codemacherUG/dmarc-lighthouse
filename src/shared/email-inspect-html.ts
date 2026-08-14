import { t, type AppLocale, type MessageKey } from './i18n'
import type {
  EmailHop,
  EmailIdentity,
  EmailInspectCheck,
  EmailInspectResult,
  EmailInspectStatus
} from './types'

export interface EmailInspectReportInput {
  result: EmailInspectResult
  locale: AppLocale
  generatedAt?: string
  appVersion?: string
}

const COLORS = {
  pass: '#2f9e5f',
  fail: '#d0453b',
  warn: '#d9a222',
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

function day(iso: string, locale: AppLocale): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return new Intl.DateTimeFormat(intl(locale), { dateStyle: 'medium' }).format(date)
}

function tr(locale: AppLocale, key: MessageKey, params?: Record<string, string | number>): string {
  return t(key, params, locale)
}

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
  .verdict {
    border: 1px solid ${COLORS.grid};
    border-left: 1.4mm solid ${COLORS.other};
    border-radius: 2mm;
    padding: 3mm 4mm;
  }
  .verdict.ok { border-left-color: ${COLORS.pass}; }
  .verdict.warn { border-left-color: ${COLORS.warn}; }
  .verdict.bad { border-left-color: ${COLORS.fail}; }
  .verdict h2 { margin: 1mm 0 0; border: 0; padding: 0; font-size: 13pt; }
  table { width: 100%; border-collapse: collapse; font-size: 9pt; }
  th, td { text-align: left; padding: 1.4mm 2mm; border-bottom: 1px solid ${COLORS.grid}; vertical-align: top; }
  th { font-size: 8pt; text-transform: uppercase; letter-spacing: .03em; color: #64708a; }
  .mono { font-family: "Cascadia Mono", Consolas, monospace; font-size: 8.5pt; }
  .muted { color: #6b7488; font-size: 8.5pt; }
  ul.findings { list-style: none; margin: 0; padding: 0; }
  li.finding { position: relative; padding-left: 5mm; margin-bottom: 2.2mm; }
  li.finding .dot { position: absolute; left: 0; top: 1.6mm; width: 2.6mm; height: 2.6mm; border-radius: 50%; }
  li.ok .dot { background: ${COLORS.pass}; }
  li.warn .dot { background: ${COLORS.warn}; }
  li.bad .dot { background: ${COLORS.fail}; }
  li.unknown .dot { background: ${COLORS.other}; }
  li.finding strong { display: block; }
  .pill { display: inline-block; padding: 0.2mm 1.6mm; border-radius: 1mm; font-size: 8pt; border: 1px solid ${COLORS.grid}; }
  .pill.ok { background: #e6f4ec; border-color: #b5dcc4; }
  .pill.warn { background: #fdf3dc; border-color: #ecd79a; }
  .pill.bad { background: #fbe6e4; border-color: #edb7b1; }
  .pill.unknown { background: #eef1f5; border-color: ${COLORS.grid}; }
  section { break-inside: avoid; }
  footer { margin-top: 8mm; padding-top: 2mm; border-top: 1px solid ${COLORS.grid}; font-size: 8pt; color: #6b7488; }
  footer .maker { margin-top: 0.8mm; }
`

function statusLabel(locale: AppLocale, status: EmailInspectStatus): string {
  return tr(locale, `email.status.${status}` as MessageKey)
}

function identityRows(identity: EmailIdentity, locale: AppLocale): string {
  const rows: Array<[MessageKey, string | null, string | null]> = [
    ['email.from', identity.from, identity.fromDisplay],
    ['email.returnPath', identity.returnPath, null],
    ['email.replyTo', identity.replyTo, null],
    ['email.to', identity.to, null],
    ['email.subject', identity.subject, null],
    ['email.date', identity.date, null],
    ['email.messageId', identity.messageId, null]
  ]
  return rows
    .filter(([, value]) => Boolean(value))
    .map(([key, value, extra]) => {
      const extraHtml = extra ? ` <span class="muted">${escapeHtml(extra)}</span>` : ''
      return `<tr><th>${escapeHtml(tr(locale, key))}</th><td class="mono">${escapeHtml(value!)}${extraHtml}</td></tr>`
    })
    .join('')
}

function checkItems(checks: EmailInspectCheck[], locale: AppLocale): string {
  return checks
    .map((item) => {
      const title = tr(locale, item.titleKey as MessageKey, item.params)
      const detail = tr(locale, item.detailKey as MessageKey, item.params)
      return `<li class="finding ${item.status}">
        <span class="dot"></span>
        <strong>${escapeHtml(title)}</strong>
        <span class="muted">${escapeHtml(statusLabel(locale, item.status))} — ${escapeHtml(detail)}</span>
      </li>`
    })
    .join('')
}

function hopTls(hop: EmailHop, locale: AppLocale): string {
  if (hop.tlsVersion) return hop.tlsVersion
  if (hop.withTls) return tr(locale, 'email.tlsImplied')
  if (hop.local) return tr(locale, 'email.hopLocal')
  return tr(locale, 'email.noTls')
}

function hopRows(hops: EmailHop[], locale: AppLocale): string {
  if (hops.length === 0) {
    return `<tr><td colspan="5" class="muted">${escapeHtml(tr(locale, 'email.hopsEmpty'))}</td></tr>`
  }
  return hops
    .map((hop) => {
      const host = hop.fromHost || hop.fromIp || '—'
      const info = hop.ipInfo
      const geo = [info?.countryCode, info?.city].filter(Boolean).join(' · ')
      const provider = info?.provider || info?.cloudProvider || info?.asOrg
      const meta = [hop.fromIp, geo, provider].filter(Boolean).join(' · ')
      const when = hop.timestamp ? hop.timestamp.replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '—'
      const by = hop.byHost ? tr(locale, 'email.hopBy', { host: hop.byHost }) : '—'
      return `<tr>
        <td>${hop.index}</td>
        <td><span class="mono">${escapeHtml(host)}</span>${
          meta ? `<div class="muted">${escapeHtml(meta)}</div>` : ''
        }</td>
        <td class="muted">${escapeHtml(by)}</td>
        <td>${escapeHtml(hopTls(hop, locale))}${
          hop.protocol ? `<div class="muted">${escapeHtml(hop.protocol)}</div>` : ''
        }</td>
        <td class="muted">${escapeHtml(when)}</td>
      </tr>`
    })
    .join('')
}

function extras(result: EmailInspectResult, locale: AppLocale): string {
  const parts: string[] = []
  if (result.dkimSignatures.length > 0) {
    const rows = result.dkimSignatures
      .map((sig) => {
        const line = tr(locale, 'email.dkimSig', {
          selector: sig.selector || '—',
          domain: sig.domain || '—'
        })
        return `<tr><td class="mono">${escapeHtml(line)}</td></tr>`
      })
      .join('')
    parts.push(
      `<section><h2>${escapeHtml(tr(locale, 'email.signatures'))}</h2><table>${rows}</table></section>`
    )
  }
  if (result.arc.length > 0) {
    const rows = result.arc
      .map(
        (set) =>
          `<tr><td class="mono">${escapeHtml(
            tr(locale, 'email.arcItem', { instance: set.instance, cv: set.cv || '—' })
          )}</td></tr>`
      )
      .join('')
    parts.push(
      `<section><h2>${escapeHtml(tr(locale, 'email.arcTitle'))}</h2><table>${rows}</table></section>`
    )
  }
  return parts.join('')
}

export function emailInspectPdfFilename(fileName: string): string {
  const trimmed = fileName.trim() || 'message'
  const base = trimmed.replace(/\.[^.\\/]+$/, '') || trimmed
  const slug =
    base
      .replace(/[^\w.-]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 80) || 'message'
  return `email-inspect-${slug}.pdf`
}

/** Self-contained HTML for an email-inspect PDF — headers only, no body. */
export function buildEmailInspectReportHtml(input: EmailInspectReportInput): string {
  const { result, locale } = input
  const generatedAt = input.generatedAt ?? new Date().toISOString()
  const verdict = tr(locale, result.verdictKey as MessageKey)
  const meta = [
    tr(locale, 'pdf.email.metaFile', { file: result.fileName }),
    tr(locale, 'pdf.metaGenerated', { date: day(generatedAt, locale) })
  ]

  return `<!DOCTYPE html>
<html lang="${locale}">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(tr(locale, 'pdf.email.title'))} — ${escapeHtml(result.fileName)}</title>
<style>${STYLES}</style>
</head>
<body>
<header class="cover">
  <div class="brand-row">
    <div class="brand-left">
      <div class="brand-mark">${BRAND_MARK}</div>
      <div>
        <div class="brand-name">DMARC Lighthouse</div>
        <span class="brand-tag">${escapeHtml(tr(locale, 'pdf.brand.tag'))}</span>
      </div>
    </div>
    <div class="brand-maker">codemacher<small>${escapeHtml(tr(locale, 'pdf.brand.makerLegal'))}</small></div>
  </div>
  <h1>${escapeHtml(tr(locale, 'pdf.email.title'))}</h1>
  <div class="subtitle">${escapeHtml(tr(locale, 'pdf.email.subtitle'))}</div>
  <div class="cover-meta">${meta.map((m) => `<span>${escapeHtml(m)}</span>`).join('')}</div>
</header>

<section class="verdict ${result.status}">
  <span class="pill ${result.status}">${escapeHtml(statusLabel(locale, result.status))}</span>
  <h2>${escapeHtml(verdict)}</h2>
</section>

<section>
  <h2>${escapeHtml(tr(locale, 'email.identity'))}</h2>
  <table>${identityRows(result.identity, locale)}</table>
</section>

<section>
  <h2>${escapeHtml(tr(locale, 'email.checks'))}</h2>
  <ul class="findings">${checkItems(result.checks, locale)}</ul>
</section>

<section>
  <h2>${escapeHtml(tr(locale, 'email.hops'))}</h2>
  <p class="muted">${escapeHtml(tr(locale, 'email.hopsHint'))}</p>
  <table>
    <thead><tr>
      <th>#</th>
      <th>${escapeHtml(tr(locale, 'pdf.email.colFrom'))}</th>
      <th>${escapeHtml(tr(locale, 'pdf.email.colBy'))}</th>
      <th>${escapeHtml(tr(locale, 'pdf.email.colTls'))}</th>
      <th>${escapeHtml(tr(locale, 'pdf.email.colWhen'))}</th>
    </tr></thead>
    <tbody>${hopRows(result.hops, locale)}</tbody>
  </table>
</section>

${extras(result, locale)}

<footer>
  ${escapeHtml(tr(locale, 'pdf.email.footer', { version: input.appVersion ?? '' }))}
  <div class="maker">${escapeHtml(tr(locale, 'pdf.footerMaker'))}</div>
</footer>
</body>
</html>`
}
