import { buildDemoAnalyzeResult, buildDemoSettings, DEMO_DNS_HTML } from '../../shared/demo-data'
import { t } from '../../shared/i18n'
import type { AppTheme } from '../../shared/theme'
import type { IpInfo } from '../../shared/types'
import { applyUiLocale } from './chrome'
import { dnsDomainEl, dnsResultEl, settingsDialog } from './dom'
import { applySettings, fillGlobalForm, openSettings, showSettingsTab } from './settings-ui'
import { clearDrill, state } from './state'
import { applyTheme } from './theme'
import { applyView, renderDetail, renderDomainAmpel, renderReports, showResult } from './view'

/** Helpers used by `npm run screenshots` (Electron capture script). */
export function installScreenshotApi(): void {
  window.__dmarcScreenshot = {
    async prepareDemo(): Promise<void> {
      applyUiLocale('de')
      applySettings(buildDemoSettings())
      fillGlobalForm(state.settings!.global)
      applyTheme('light')
      state.selectedReportId = null
      clearDrill()
      showResult(buildDemoAnalyzeResult(), t('status.cached', { count: 12 }))
      dnsDomainEl.value = 'example.com'
      dnsResultEl.innerHTML = DEMO_DNS_HTML
      dnsResultEl.className = 'dns-result ok'
      // Seed PTR / Geo labels without calling the network.
      const seedDemoIps = (): void => {
        const demoIp = (
          ip: string,
          ptr: string | null,
          provider: string | null,
          extra: Partial<IpInfo> = {}
        ): void => {
          state.ipLabelCache.set(ip, {
            ip,
            ptr,
            provider,
            country: extra.country ?? null,
            countryCode: extra.countryCode ?? null,
            city: extra.city ?? null,
            lat: extra.lat ?? null,
            lon: extra.lon ?? null,
            asn: extra.asn ?? null,
            asOrg: extra.asOrg ?? null,
            cloudProvider: extra.cloudProvider ?? null,
            dnsblHits: extra.dnsblHits ?? [],
            geoSource: extra.geoSource ?? 'none'
          })
        }
        demoIp('192.0.2.10', 'mail-a.example.net', 'Example Net', {
          countryCode: 'DE',
          city: 'Berlin',
          lat: 52.52,
          lon: 13.405,
          asn: 64496,
          cloudProvider: null
        })
        demoIp('192.0.2.40', 'smtp.example.net', 'Example Net', {
          countryCode: 'DE',
          city: 'Frankfurt',
          lat: 50.11,
          lon: 8.68,
          asn: 64496
        })
        demoIp('192.0.2.41', 'smtp-b.example.net', 'Example Net', {
          countryCode: 'DE',
          city: 'München',
          lat: 48.137,
          lon: 11.575,
          asn: 64496
        })
        demoIp('192.0.2.80', 'mx.gmx.example', 'GMX', {
          countryCode: 'DE',
          city: 'Karlsruhe',
          lat: 49.0069,
          lon: 8.4037,
          asn: 6805
        })
        demoIp('198.51.100.20', null, null, {
          countryCode: 'US',
          city: 'Mountain View',
          lat: 37.386,
          lon: -122.084,
          asn: 15169,
          cloudProvider: 'Google',
          dnsblHits: []
        })
        demoIp('198.51.100.55', 'mta.yahoo.example', 'Yahoo', {
          countryCode: 'US',
          city: 'Sunnyvale',
          lat: 37.3688,
          lon: -122.0363,
          asn: 10310
        })
        demoIp('203.0.113.15', null, null, {
          countryCode: 'NL',
          city: 'Amsterdam',
          lat: 52.3676,
          lon: 4.9041,
          dnsblHits: ['spamhaus-zen']
        })
        demoIp('203.0.113.80', null, null, {
          countryCode: 'FR',
          city: 'Paris',
          lat: 48.8566,
          lon: 2.3522
        })
        demoIp('2001:db8:1::10', 'ipv6.example.net', 'Example Net', {
          countryCode: 'DE',
          city: 'Berlin',
          lat: 52.52,
          lon: 13.405,
          asn: 64496
        })
        demoIp('2001:db8:2::22', 'ipv6-b.example.net', 'Example Net', {
          countryCode: 'AT',
          city: 'Wien',
          lat: 48.2082,
          lon: 16.3738,
          asn: 64496
        })
      }
      seedDemoIps()
      state.domainHealthCache = [
        {
          domain: 'example.com',
          total: 100,
          passing: 98,
          failing: 2,
          passRate: 98,
          dkimSelectors: ['selector1'],
          dmarcPolicy: 'reject',
          spfOk: true,
          dkimOk: true,
          status: 'ok',
          reasons: ['health.reason.ok']
        }
      ]
      renderDomainAmpel(state.domainHealthCache)
      applyView()
      settingsDialog.close()
      // Async IP enrichment can overwrite demo coords — re-seed afterwards.
      await new Promise((r) => setTimeout(r, 900))
      seedDemoIps()
      applyView()
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
    },
    openSettingsDemo(): void {
      openSettings()
      showSettingsTab('account')
    },
    closeSettings(): void {
      settingsDialog.close()
    },
    setTheme(theme: AppTheme): void {
      applyTheme(theme)
    },
    async scrollTo(selector: string): Promise<void> {
      const el = document.querySelector(selector)
      if (el) el.scrollIntoView({ block: 'start' })
      await new Promise((r) => setTimeout(r, 200))
    },
    async selectFirstReport(): Promise<void> {
      const first = state.fullResult?.reports[0]
      if (!first) return
      state.selectedReportId = first.reportId
      renderReports(state.viewResult)
      renderDetail(first)
      await new Promise((r) => setTimeout(r, 100))
    },
    async prepareFullPage(): Promise<{ width: number; height: number }> {
      settingsDialog.close()
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' })
      document.documentElement.classList.add('screenshot-full')
      document.body.classList.add('screenshot-full')
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      const app = document.getElementById('app')
      const width = Math.ceil(
        Math.max(document.documentElement.scrollWidth, app?.scrollWidth ?? 0, 1400)
      )
      const height = Math.ceil(
        Math.max(
          document.documentElement.scrollHeight,
          document.body.scrollHeight,
          app?.scrollHeight ?? 0
        )
      )
      return { width, height }
    }
  }
}
