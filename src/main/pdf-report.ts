import { BrowserWindow, app } from 'electron'
import { spawn, spawnSync } from 'child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { pathToFileURL } from 'url'
import { buildDomainStats, mergeDomainHealth } from '../shared/analyze'
import { getLocale, t } from '../shared/i18n'
import { buildManagementReportHtml, type ManagementReportInput } from '../shared/report-html'
import type { ReportPeriod } from '../shared/report-period'
import type {
  AnalyzeResult,
  DnsCheckResult,
  DomainHealth,
  ForensicReportRow,
  ReportRow
} from '../shared/types'

const FRAME_ID = '__dmarc_pdf_frame'
const STYLE_ID = '__dmarc_pdf_style'
const PDF_MAGIC = Buffer.from('%PDF')

/** Serialize PDF jobs — two overlays in the same renderer would clobber each other. */
let pdfLock: Promise<void> = Promise.resolve()

/**
 * Runs in the renderer. An about:blank iframe stays same-origin, so we can
 * document.write the report without touching CSP (blob:/srcdoc would be blocked).
 */
const INJECT_PRINT_FRAME = `function (html, frameId, styleId) {
  return new Promise((resolve, reject) => {
    document.getElementById(frameId)?.remove()
    document.getElementById(styleId)?.remove()
    const style = document.createElement('style')
    style.id = styleId
    style.textContent =
      '@page{size:A4;margin:14mm 12mm 16mm}' +
      '@media print{' +
      'html,body{margin:0!important;padding:0!important;background:#fff!important}' +
      'body>:not(#' + frameId + '){display:none!important}' +
      '#' + frameId + '{display:block!important;position:static!important;width:100%!important;height:auto!important;border:0!important;opacity:1!important}' +
      '}'
    document.head.appendChild(style)
    const frame = document.createElement('iframe')
    frame.id = frameId
    frame.setAttribute('aria-hidden', 'true')
    frame.style.cssText =
      'position:fixed;right:100%;bottom:100%;width:210mm;min-height:297mm;border:0;opacity:0;pointer-events:none'
    document.body.appendChild(frame)
    const doc = frame.contentDocument
    if (!doc) {
      reject(new Error('No iframe document'))
      return
    }
    doc.open()
    doc.write(html)
    doc.close()
    requestAnimationFrame(() => resolve(true))
  })
}`

const REMOVE_PRINT_FRAME = `function (frameId, styleId) {
  document.getElementById(frameId)?.remove()
  document.getElementById(styleId)?.remove()
  return true
}`

export function looksLikePdf(data: Buffer): boolean {
  return data.length > 5 && data.subarray(0, 4).equals(PDF_MAGIC)
}

/** Chrome/Chromium binaries we can ask to print, in preference order. */
export function chromeCandidates(): string[] {
  const extra = [process.env.CHROME_PATH, process.env.GOOGLE_CHROME_BIN].filter((v): v is string =>
    Boolean(v)
  )
  if (process.platform === 'darwin') {
    return [
      ...extra,
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium'
    ]
  }
  if (process.platform === 'win32') {
    const pf = process.env.PROGRAMFILES ?? 'C:\\Program Files'
    const pf86 = process.env['PROGRAMFILES(X86)'] ?? 'C:\\Program Files (x86)'
    const local = process.env.LOCALAPPDATA ?? ''
    return [
      ...extra,
      join(pf, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      join(pf86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      join(local, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      join(pf, 'Chromium', 'Application', 'chrome.exe')
    ]
  }
  return [
    ...extra,
    'google-chrome-stable',
    'google-chrome',
    'chromium-browser',
    'chromium',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/snap/bin/chromium'
  ]
}

function resolveOnPath(cmd: string): string | null {
  if (/[\\/]/.test(cmd) || cmd.endsWith('.exe')) {
    return existsSync(cmd) ? cmd : null
  }
  const tool = process.platform === 'win32' ? 'where' : 'which'
  const result = spawnSync(tool, [cmd], { encoding: 'utf8' })
  if (result.status !== 0) return null
  const first = (result.stdout ?? '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .find(Boolean)
  return first || null
}

export function resolveChrome(): string | null {
  for (const candidate of chromeCandidates()) {
    const resolved = resolveOnPath(candidate)
    if (resolved) return resolved
  }
  return null
}

function runChromePrint(
  bin: string,
  htmlFile: string,
  pdfFile: string,
  profile: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = [
      '--headless',
      '--disable-gpu',
      '--no-sandbox',
      '--disable-dev-shm-usage',
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--no-pdf-header-footer',
      `--print-to-pdf=${pdfFile}`,
      pathToFileURL(htmlFile).href
    ]
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] })
    let stderr = ''
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk)
    })
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      reject(new Error('timeout'))
    }, 45_000)
    child.on('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      if (existsSync(pdfFile)) {
        resolve()
        return
      }
      const hint = stderr.trim().slice(-400) || `exit ${code ?? '?'}`
      reject(new Error(hint))
    })
  })
}

/**
 * Print with a system Chrome/Chromium. Electron's own print compositor cannot
 * allocate shared memory on this Linux setup (`disable-dev-shm-usage` + ESRCH).
 */
async function printWithChrome(html: string): Promise<Buffer> {
  const chrome = resolveChrome()
  if (!chrome) throw new Error(t('main.pdfNoChrome'))
  const dir = mkdtempSync(join(tmpdir(), 'dmarc-pdf-'))
  const htmlFile = join(dir, 'report.html')
  const pdfFile = join(dir, 'report.pdf')
  const profile = join(dir, 'profile')
  mkdirSync(profile)
  writeFileSync(htmlFile, html, 'utf8')
  try {
    await runChromePrint(chrome, htmlFile, pdfFile, profile)
    const data = readFileSync(pdfFile)
    if (!looksLikePdf(data)) throw new Error(t('main.pdfNoChrome'))
    return data
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

async function whenRendererReady(win: BrowserWindow): Promise<void> {
  const wc = win.webContents
  if (!wc.isLoadingMainFrame()) return
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(t('main.pdfNoWindow'))), 15_000)
    wc.once('did-finish-load', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}

/** Electron printToPDF — works on Windows/macOS, fails on this Linux shm setup. */
async function printHtmlInHost(win: BrowserWindow, html: string): Promise<Buffer> {
  await whenRendererReady(win)
  const wc = win.webContents
  try {
    await wc.executeJavaScript(
      `(${INJECT_PRINT_FRAME})(${JSON.stringify(html)},${JSON.stringify(FRAME_ID)},${JSON.stringify(STYLE_ID)})`
    )
    const data = await wc.printToPDF({
      pageSize: 'A4',
      printBackground: true,
      preferCSSPageSize: true,
      margins: { marginType: 'none' }
    })
    if (!looksLikePdf(data)) throw new Error('Printing failed')
    return data
  } finally {
    if (!win.isDestroyed() && !wc.isDestroyed()) {
      await wc
        .executeJavaScript(
          `(${REMOVE_PRINT_FRAME})(${JSON.stringify(FRAME_ID)},${JSON.stringify(STYLE_ID)})`
        )
        .catch(() => undefined)
    }
  }
}

function hostUsable(host?: BrowserWindow | null): host is BrowserWindow {
  return Boolean(host && !host.isDestroyed() && !host.webContents.isDestroyed())
}

/**
 * Render the management-report HTML to PDF.
 * Linux prefers system Chrome because Electron's print compositor cannot
 * create shared memory here. Other platforms try Electron first.
 */
export async function renderHtmlToPdf(html: string, host?: BrowserWindow | null): Promise<Buffer> {
  let release: () => void = () => undefined
  const previous = pdfLock
  pdfLock = new Promise<void>((resolve) => {
    release = resolve
  })
  await previous
  const errors: string[] = []
  const tryChrome = async (): Promise<Buffer | null> => {
    try {
      return await printWithChrome(html)
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err))
      return null
    }
  }
  const tryElectron = async (): Promise<Buffer | null> => {
    if (!hostUsable(host)) return null
    try {
      return await printHtmlInHost(host, html)
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err))
      return null
    }
  }
  try {
    const first = process.platform === 'linux' ? tryChrome : tryElectron
    const second = process.platform === 'linux' ? tryElectron : tryChrome
    const pdf = (await first()) ?? (await second())
    if (pdf) return pdf
    if (errors.some((e) => e === t('main.pdfNoChrome')) && process.platform === 'linux') {
      throw new Error(t('main.pdfNoChrome'))
    }
    throw new Error(t('main.pdfFailed', { message: errors.join(' · ') || t('main.pdfNoWindow') }))
  } finally {
    release()
  }
}

export interface PdfReportOptions {
  /** Covered month as `YYYY-MM`; without it the data range is shown. */
  month?: string
  domain?: string | null
  account?: string | null
  domains?: DomainHealth[]
  generatedAt?: string
  /** Live main window, used when Electron's own printToPDF is available. */
  host?: BrowserWindow | null
}

/** Build the management report PDF for an already analyzed result. */
export async function buildPdfReport(
  result: AnalyzeResult,
  options: PdfReportOptions = {}
): Promise<Buffer> {
  const { host, ...rest } = options
  const input: ManagementReportInput = {
    result,
    locale: getLocale(),
    appVersion: app.getVersion(),
    ...rest
  }
  return renderHtmlToPdf(buildManagementReportHtml(input), host)
}

/** Reports whose measurement window overlaps the period. */
export function reportsInPeriod(reports: ReportRow[], period: ReportPeriod): ReportRow[] {
  const from = new Date(period.from).getTime()
  const to = new Date(period.to).getTime()
  return reports.filter((report) => {
    const begin = Date.parse(report.dateBegin)
    const end = Date.parse(report.dateEnd)
    const start = Number.isNaN(begin) ? end : begin
    const stop = Number.isNaN(end) ? begin : end
    if (Number.isNaN(start) || Number.isNaN(stop)) return false
    return stop >= from && start < to
  })
}

export function forensicInPeriod(
  rows: ForensicReportRow[],
  period: ReportPeriod
): ForensicReportRow[] {
  const from = new Date(period.from).getTime()
  const to = new Date(period.to).getTime()
  return rows.filter((row) => {
    const at = row.arrivalDate ? Date.parse(row.arrivalDate) : NaN
    return !Number.isNaN(at) && at >= from && at < to
  })
}

/** One domain's slice of a monthly run — the mailbox is only the source, not the subject. */
export interface DomainReportSlice {
  domain: string
  reports: ReportRow[]
  forensicReports: ForensicReportRow[]
  accountLabels: string[]
}

function domainKey(value: string | null | undefined): string | null {
  const key = (value ?? '').trim().toLowerCase().replace(/\.$/, '')
  return key || null
}

/**
 * Split cached reports by the DMARC org domain. One IMAP mailbox can hold any
 * number of domains; the management PDF is one file per domain. The same domain
 * from several accounts is merged (deduped by report id + org).
 */
export function groupReportsByDomain(
  sources: Array<{
    label: string | null
    reports: ReportRow[]
    forensicReports: ForensicReportRow[]
  }>
): DomainReportSlice[] {
  const map = new Map<
    string,
    DomainReportSlice & { seenReports: Set<string>; seenForensic: Set<string> }
  >()
  const bucket = (domain: string, label: string | null) => {
    let slice = map.get(domain)
    if (!slice) {
      slice = {
        domain,
        reports: [],
        forensicReports: [],
        accountLabels: [],
        seenReports: new Set(),
        seenForensic: new Set()
      }
      map.set(domain, slice)
    }
    if (label && !slice.accountLabels.includes(label)) slice.accountLabels.push(label)
    return slice
  }

  for (const source of sources) {
    for (const report of source.reports) {
      const domain = domainKey(report.domain)
      if (!domain) continue
      const slice = bucket(domain, source.label)
      const id = `${report.orgName}\0${report.reportId}`
      if (slice.seenReports.has(id)) continue
      slice.seenReports.add(id)
      slice.reports.push(report)
    }
    for (const row of source.forensicReports) {
      const domain = domainKey(row.reportedDomain)
      if (!domain) continue
      const slice = bucket(domain, source.label)
      const id = row.id || `${row.sourceIp}\0${row.arrivalDate}\0${row.headerFrom}`
      if (slice.seenForensic.has(id)) continue
      slice.seenForensic.add(id)
      slice.forensicReports.push(row)
    }
  }

  return [...map.values()]
    .map((slice) => ({
      domain: slice.domain,
      reports: slice.reports,
      forensicReports: slice.forensicReports,
      accountLabels: slice.accountLabels
    }))
    .sort((a, b) => a.domain.localeCompare(b.domain))
}

export function domainHealthFromReports(
  reports: ReportRow[],
  dnsFor?: (domain: string, selectors: string[]) => DnsCheckResult | null
): DomainHealth[] {
  return buildDomainStats(reports)
    .map((stats) => mergeDomainHealth(stats, dnsFor?.(stats.domain, stats.dkimSelectors) ?? null))
    .sort((a, b) => b.total - a.total)
}

/** Default output directory when the user did not pick one. */
export function defaultReportDir(): string {
  return join(app.getPath('documents'), 'DMARC Lighthouse')
}

export function writeReportFile(dir: string, filename: string, data: Buffer): string {
  mkdirSync(dir, { recursive: true })
  const target = join(dir, filename)
  writeFileSync(target, data)
  return target
}
