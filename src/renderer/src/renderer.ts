import { t } from '../../shared/i18n'
import { initActions } from './actions'
import { initChrome, setAfterLocaleChange, setStatus } from './chrome'
import { aboutVersionEl } from './dom'
import { installScreenshotApi } from './screenshots'
import { initSettingsUi, loadSettings, refreshSettingsLocale } from './settings-ui'
import { state } from './state'
import { applyView, initView, showResult } from './view'

setAfterLocaleChange(() => {
  refreshSettingsLocale()
  if (state.fullResult) {
    showResult(state.fullResult)
  } else {
    applyView()
  }
})

initChrome()
initView()
initSettingsUi()
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
