import {
  buildDemoAnalyzeResult,
  buildDemoEmailInspect,
  buildDemoSettings,
  DEMO_ROLLOUT_DNS,
  DEMO_TRANSPORT
} from '../../shared/demo-data'
import { t, type AppLocale } from '../../shared/i18n'
import type { AppTheme } from '../../shared/theme'
import { DEFAULT_DATE_RANGE, type IpInfo } from '../../shared/types'
import { applyUiLocale } from './chrome'
import { escapeHtml } from './format'
import {
  dnsDialog,
  dnsDomainEl,
  dnsResultEl,
  emailInspectDialog,
  filterRangeEl,
  rolloutDialog,
  settingsDialog
} from './dom'
import { openEmailInspect, seedEmailInspect } from './email-inspect-ui'
import { openRollout, seedRolloutDns } from './rollout-ui'
import { renderTransportSecurity } from './transport-view'
import { applySettings, fillGlobalForm, openSettings, showSettingsTab } from './settings-ui'
import { clearDrill, state } from './state'
import { applyTheme } from './theme'
import { applyView, renderDetail, renderDomainAmpel, renderReports, showResult } from './view'

function fillDnsDemo(): void {
  dnsDomainEl.value = 'example.com'
  const dmarcLine = t('dns.dmarcFound', {
    policy: 'reject',
    rua: 'mailto:dmarc@example.com',
    ruf: 'mailto:dmarc@example.com'
  })
  const spfLine = t('dns.spfFound', { record: 'v=spf1 include:_spf.example.net -all' })
  const dkimHtml = t('dns.dkimLine', {
    selector: '<span class="mono">selector1</span>',
    state: `<span class="pass">${escapeHtml(t('dns.dkimFound'))}</span>`
  })
  dnsResultEl.innerHTML = `<strong>example.com</strong><br />${escapeHtml(dmarcLine)}<br /><span class="mono">${escapeHtml(spfLine)}</span><br />${dkimHtml}`
  dnsResultEl.className = 'dns-result ok'
}

/** Helpers used by `npm run screenshots` (Electron capture script). */
export function installScreenshotApi(): void {
  window.__dmarcScreenshot = {
    async prepareDemo(locale: AppLocale = 'de'): Promise<void> {
      if (settingsDialog.open) settingsDialog.close()
      if (dnsDialog.open) dnsDialog.close()
      if (rolloutDialog.open) rolloutDialog.close()
      if (emailInspectDialog.open) emailInspectDialog.close()
      document.documentElement.classList.remove('screenshot-full', 'screenshot-dialog')
      document.body.classList.remove('screenshot-full')
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' })
      applyUiLocale(locale)
      applySettings(buildDemoSettings(locale))
      fillGlobalForm(state.settings!.global)
      applyTheme('light')
      state.selectedReportId = null
      clearDrill()
      filterRangeEl.value = DEFAULT_DATE_RANGE
      showResult(buildDemoAnalyzeResult(), t('status.cached', { count: 12 }))
      fillDnsDemo()
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
            senderKind: extra.senderKind ?? null,
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
    openDnsDemo(): void {
      fillDnsDemo()
      dnsResultEl.classList.remove('hidden')
      renderTransportSecurity(DEMO_TRANSPORT)
      dnsDialog.showModal()
    },
    closeDns(): void {
      dnsDialog.close()
    },
    openRolloutDemo(): void {
      seedRolloutDns('example.com', DEMO_ROLLOUT_DNS)
      openRollout()
    },
    closeRollout(): void {
      rolloutDialog.close()
    },
    openEmailInspectDemo(): { width: number; height: number } {
      document.getElementById('email-inspect-paste')?.removeAttribute('open')
      document.documentElement.classList.add('screenshot-dialog')
      seedEmailInspect(buildDemoEmailInspect())
      openEmailInspect()
      return {
        width: Math.ceil(emailInspectDialog.scrollWidth),
        height: Math.ceil(emailInspectDialog.scrollHeight)
      }
    },
    closeEmailInspect(): void {
      emailInspectDialog.close()
      document.documentElement.classList.remove('screenshot-dialog')
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
