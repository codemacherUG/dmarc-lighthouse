import { t } from '../../shared/i18n'
import { initActions } from './actions'
import { initChrome, setAfterLocaleChange, setStatus } from './chrome'
import { initTheme } from './theme'
import { aboutVersionEl } from './dom'
import { installScreenshotApi } from './screenshots'
import { initSettingsUi, loadSettings, refreshSettingsLocale } from './settings-ui'
import { state } from './state'
import { applyView, initView, showResult } from './view'
import { initRolloutUi, refreshRolloutLocale } from './rollout-ui'
import { initEmailInspectUi, refreshEmailInspectLocale } from './email-inspect-ui'
import { initSpfWizardUi, refreshSpfBuilderLocale } from './spf-wizard-ui'
import { initTlsrptWizardUi, refreshTlsrptBuilderLocale } from './tlsrpt-wizard-ui'
import { initMtaStsWizardUi, refreshMtaStsBuilderLocale } from './mta-sts-wizard-ui'
import { initWizardUi, refreshBuilderLocale } from './wizard-ui'

setAfterLocaleChange(() => {
  refreshSettingsLocale()
  refreshBuilderLocale()
  refreshSpfBuilderLocale()
  refreshTlsrptBuilderLocale()
  refreshMtaStsBuilderLocale()
  refreshRolloutLocale()
  refreshEmailInspectLocale()
  if (state.fullResult) {
    showResult(state.fullResult)
  } else {
    applyView()
  }
})

initChrome()
initTheme()
initView()
initSettingsUi()
initWizardUi()
initSpfWizardUi()
initTlsrptWizardUi()
initMtaStsWizardUi()
initRolloutUi()
initEmailInspectUi()
initActions()
installScreenshotApi()

void (async () => {
  try {
    aboutVersionEl.textContent = await window.api.getAppVersion()
    await loadSettings()
    const cached = await window.api.loadCache()
    if (cached && cached.reports.length > 0) {
      showResult(cached, t('status.cached', { count: cached.aggregate.reportCount }))
    }
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  }
})()
