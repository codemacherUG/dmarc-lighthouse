export const statusEl = document.getElementById('status') as HTMLDivElement
export const statusLogListEl = document.getElementById('status-log-list') as HTMLUListElement
export const statusLogDialog = document.getElementById('status-log-dialog') as HTMLDialogElement
export const btnStatusLog = document.getElementById('btn-status-log') as HTMLButtonElement
export const btnCloseStatusLog = document.getElementById(
  'btn-close-status-log'
) as HTMLButtonElement
export const btnStatusLogOk = document.getElementById('btn-status-log-ok') as HTMLButtonElement
export const topProgressEl = document.getElementById('top-progress') as HTMLDivElement
export const progressEl = document.getElementById('progress') as HTMLDivElement
export const progressLabelEl = document.getElementById('progress-label') as HTMLElement
export const reportsBody = document.getElementById('reports-body') as HTMLTableSectionElement
export const detailEl = document.getElementById('detail') as HTMLDivElement
export const tableOrgs = document.getElementById('table-orgs') as HTMLTableSectionElement
export const tableIps = document.getElementById('table-ips') as HTMLTableSectionElement
export const tableFrom = document.getElementById('table-from') as HTMLTableSectionElement
export const dropOverlay = document.getElementById('drop-overlay') as HTMLDivElement
export const filterRangeEl = document.getElementById('filter-range') as HTMLSelectElement
export const filterCustomWrap = document.getElementById('filter-custom-range') as HTMLLabelElement
export const filterFromEl = document.getElementById('filter-from') as HTMLInputElement
export const filterToEl = document.getElementById('filter-to') as HTMLInputElement
export const filterDomainEl = document.getElementById('filter-domain') as HTMLSelectElement
export const filterHideGoogleNoiseEl = document.getElementById(
  'filter-hide-google-noise'
) as HTMLInputElement
export const filterChipsEl = document.getElementById('filter-chips') as HTMLDivElement
export const filterPanelEl = document.getElementById('filter-panel') as HTMLElement
export const btnFilterReset = document.getElementById('btn-filter-reset') as HTMLButtonElement
export const accountFieldEl = document.getElementById('account-field') as HTMLLabelElement
export const accountSelectEl = document.getElementById('account-select') as HTMLSelectElement
export const dnsDomainEl = document.getElementById('dns-domain') as HTMLInputElement
export const dnsSelectorsEl = document.getElementById('dns-selectors') as HTMLInputElement
export const dnsResultEl = document.getElementById('dns-result') as HTMLDivElement
export const dnsTransportEl = document.getElementById('dns-transport') as HTMLDivElement
export const domainAmpelEl = document.getElementById('domain-ampel') as HTMLDivElement
export const tableProblemSources = document.getElementById(
  'table-problem-sources'
) as HTMLTableSectionElement
export const ipMapEl = document.getElementById('ip-map') as HTMLDivElement
export const ipMapEmptyEl = document.getElementById('ip-map-empty') as HTMLParagraphElement
export const ipDetailDialog = document.getElementById('ip-detail-dialog') as HTMLDialogElement
export const ipDetailBody = document.getElementById('ip-detail-body') as HTMLDivElement
export const btnCloseIpDetail = document.getElementById('btn-close-ip-detail') as HTMLButtonElement
export const btnIpRdap = document.getElementById('btn-ip-rdap') as HTMLButtonElement
export const btnIpFilter = document.getElementById('btn-ip-filter') as HTMLButtonElement

export const navDashboard = document.getElementById('nav-dashboard') as HTMLButtonElement
export const navTools = document.getElementById('nav-tools') as HTMLButtonElement
export const toolsMenu = document.getElementById('tools-menu') as HTMLDivElement
export const navDns = document.getElementById('nav-dns') as HTMLButtonElement
export const btnSettings = document.getElementById('btn-settings') as HTMLButtonElement
export const btnBuilder = document.getElementById('btn-builder') as HTMLButtonElement
export const btnSpfBuilder = document.getElementById('btn-spf-builder') as HTMLButtonElement
export const btnTlsrptBuilder = document.getElementById('btn-tlsrpt-builder') as HTMLButtonElement
export const btnMtaStsBuilder = document.getElementById('btn-mta-sts-builder') as HTMLButtonElement
export const btnRollout = document.getElementById('btn-rollout') as HTMLButtonElement
export const btnEmailInspect = document.getElementById('btn-email-inspect') as HTMLButtonElement
export const emailInspectDialog = document.getElementById(
  'email-inspect-dialog'
) as HTMLDialogElement
export const btnCloseEmailInspect = document.getElementById(
  'btn-close-email-inspect'
) as HTMLButtonElement
export const btnEmailInspectOpen = document.getElementById(
  'btn-email-inspect-open'
) as HTMLButtonElement
export const btnEmailInspectPaste = document.getElementById(
  'btn-email-inspect-paste'
) as HTMLButtonElement
export const emailInspectPasteEl = document.getElementById(
  'email-inspect-paste-text'
) as HTMLTextAreaElement
export const emailInspectResultEl = document.getElementById(
  'email-inspect-result'
) as HTMLDivElement
export const rolloutDialog = document.getElementById('rollout-dialog') as HTMLDialogElement
export const btnCloseRollout = document.getElementById('btn-close-rollout') as HTMLButtonElement
export const btnRolloutRefresh = document.getElementById('btn-rollout-refresh') as HTMLButtonElement
export const rolloutDomainEl = document.getElementById('rollout-domain') as HTMLSelectElement
export const rolloutResultEl = document.getElementById('rollout-result') as HTMLDivElement
export const btnInfo = document.getElementById('btn-info') as HTMLButtonElement
export const btnFetch = document.getElementById('btn-fetch') as HTMLButtonElement
export const btnOpenFiles = document.getElementById('btn-open-files') as HTMLButtonElement
export const btnExport = document.getElementById('btn-export') as HTMLButtonElement
export const btnDns = document.getElementById('btn-dns') as HTMLButtonElement
export const btnCloseDns = document.getElementById('btn-close-dns') as HTMLButtonElement
export const settingsDialog = document.getElementById('settings-dialog') as HTMLDialogElement
export const builderDialog = document.getElementById('builder-dialog') as HTMLDialogElement
export const infoDialog = document.getElementById('info-dialog') as HTMLDialogElement
export const exportDialog = document.getElementById('export-dialog') as HTMLDialogElement
export const dnsDialog = document.getElementById('dns-dialog') as HTMLDialogElement
export const dnsForm = document.getElementById('dns-form') as HTMLFormElement
export const createMailboxDialog = document.getElementById(
  'create-mailbox-dialog'
) as HTMLDialogElement
export const createMailboxPathEl = document.getElementById(
  'create-mailbox-path'
) as HTMLInputElement
export const createMailboxStatusEl = document.getElementById(
  'create-mailbox-status'
) as HTMLParagraphElement
export const btnCloseCreateMailbox = document.getElementById(
  'btn-close-create-mailbox'
) as HTMLButtonElement
export const btnCancelCreateMailbox = document.getElementById(
  'btn-cancel-create-mailbox'
) as HTMLButtonElement
export const btnConfirmCreateMailbox = document.getElementById(
  'btn-confirm-create-mailbox'
) as HTMLButtonElement
export const settingsForm = document.getElementById('settings-form') as HTMLFormElement
export const btnCloseSettings = document.getElementById('btn-close-settings') as HTMLButtonElement
export const btnCloseBuilder = document.getElementById('btn-close-builder') as HTMLButtonElement
export const btnCloseInfo = document.getElementById('btn-close-info') as HTMLButtonElement
export const btnCloseExport = document.getElementById('btn-close-export') as HTMLButtonElement
export const btnInfoOk = document.getElementById('btn-info-ok') as HTMLButtonElement
export const btnOpenLicenses = document.getElementById('btn-open-licenses') as HTMLButtonElement
export const btnCheckUpdate = document.getElementById('btn-check-update') as HTMLButtonElement
export const btnTest = document.getElementById('btn-test') as HTMLButtonElement
export const btnClearCache = document.getElementById('btn-clear-cache') as HTMLButtonElement
export const btnExportCsv = document.getElementById('btn-export-csv') as HTMLButtonElement
export const btnExportJson = document.getElementById('btn-export-json') as HTMLButtonElement
export const btnExportPdf = document.getElementById('btn-export-pdf') as HTMLButtonElement
export const passwordHintEl = document.getElementById('password-hint') as HTMLParagraphElement
export const settingsStatusEl = document.getElementById('settings-status') as HTMLParagraphElement
export const aboutVersionEl = document.getElementById('about-version') as HTMLSpanElement
export const updateCheckStatusEl = document.getElementById(
  'update-check-status'
) as HTMLParagraphElement
export const updateBanner = document.getElementById('update-banner') as HTMLDivElement
export const updateBannerText = document.getElementById('update-banner-text') as HTMLSpanElement
export const btnUpdateInstall = document.getElementById('btn-update-install') as HTMLButtonElement
export const btnUpdateDismiss = document.getElementById('btn-update-dismiss') as HTMLButtonElement

export const settingsAccountSelectEl = document.getElementById(
  'settings-account-select'
) as HTMLSelectElement
export const btnNewAccount = document.getElementById('btn-new-account') as HTMLButtonElement
export const btnDeleteAccount = document.getElementById('btn-delete-account') as HTMLButtonElement
export const tabBtnAccount = document.getElementById('tab-btn-account') as HTMLButtonElement
export const tabBtnAppearance = document.getElementById('tab-btn-appearance') as HTMLButtonElement
export const tabBtnGeneral = document.getElementById('tab-btn-general') as HTMLButtonElement
export const tabBtnEnrichment = document.getElementById('tab-btn-enrichment') as HTMLButtonElement
export const tabAccountEl = document.getElementById('tab-account') as HTMLElement
export const tabAppearanceEl = document.getElementById('tab-appearance') as HTMLElement
export const tabGeneralEl = document.getElementById('tab-general') as HTMLElement
export const tabEnrichmentEl = document.getElementById('tab-enrichment') as HTMLElement

export const providerEl = document.getElementById('provider') as HTMLSelectElement
export const authModeEl = document.getElementById('authMode') as HTMLSelectElement
export const accountNameEl = document.getElementById('accountName') as HTMLInputElement
export const hostEl = document.getElementById('host') as HTMLInputElement
export const portEl = document.getElementById('port') as HTMLInputElement
export const secureEl = document.getElementById('secure') as HTMLInputElement
export const userEl = document.getElementById('user') as HTMLInputElement
export const passwordEl = document.getElementById('password') as HTMLInputElement
export const passwordFieldEl = document.getElementById('password-field') as HTMLElement
export const oauthActionsEl = document.getElementById('oauth-actions') as HTMLElement
export const oauthClientIdsEl = document.getElementById('oauth-client-ids') as HTMLElement
export const oauthGoogleFieldEl = document.getElementById('oauth-google-field') as HTMLElement
export const oauthMicrosoftFieldEl = document.getElementById('oauth-microsoft-field') as HTMLElement
export const oauthSetupGoogleEl = document.getElementById('oauth-setup-google') as HTMLElement
export const oauthSetupMicrosoftEl = document.getElementById('oauth-setup-microsoft') as HTMLElement
export const btnOauthLogin = document.getElementById('btn-oauth-login') as HTMLButtonElement
export const btnOauthDisconnect = document.getElementById(
  'btn-oauth-disconnect'
) as HTMLButtonElement
export const mailboxEl = document.getElementById('mailbox') as HTMLInputElement
export const archiveMailboxEl = document.getElementById('archiveMailbox') as HTMLInputElement
export const btnClearArchiveMailbox = document.getElementById(
  'btn-clear-archive-mailbox'
) as HTMLButtonElement
export const subjectFilterEl = document.getElementById('subjectFilter') as HTMLInputElement
export const markSeenAfterFetchEl = document.getElementById(
  'markSeenAfterFetch'
) as HTMLInputElement
export const autoFetchMinutesEl = document.getElementById('autoFetchMinutes') as HTMLInputElement
export const runInTrayEl = document.getElementById('runInTray') as HTMLInputElement
export const openAtLoginEl = document.getElementById('openAtLogin') as HTMLInputElement
export const pdfMonthlyEnabledEl = document.getElementById('pdfMonthlyEnabled') as HTMLInputElement
export const pdfMonthlyDirEl = document.getElementById('pdfMonthlyDir') as HTMLInputElement
export const btnPdfDir = document.getElementById('btn-pdf-dir') as HTMLButtonElement
export const btnPdfNow = document.getElementById('btn-pdf-now') as HTMLButtonElement
export const pdfMonthlyLastEl = document.getElementById('pdf-monthly-last') as HTMLSpanElement
export const notifyOnFailEl = document.getElementById('notifyOnFail') as HTMLInputElement
export const notifyNewSourceEl = document.getElementById('notifyNewSource') as HTMLInputElement
export const passRateAlertThresholdEl = document.getElementById(
  'passRateAlertThreshold'
) as HTMLInputElement
export const ignoredSourcesEl = document.getElementById('ignoredSources') as HTMLTextAreaElement
export const languageEl = document.getElementById('language') as HTMLSelectElement
export const themeEl = document.getElementById('theme') as HTMLSelectElement
export const oauthGoogleClientIdEl = document.getElementById(
  'oauthGoogleClientId'
) as HTMLInputElement
export const oauthMicrosoftClientIdEl = document.getElementById(
  'oauthMicrosoftClientId'
) as HTMLInputElement
export const enrichmentEnabledEl = document.getElementById('enrichmentEnabled') as HTMLInputElement
export const cloudRangesEnabledEl = document.getElementById(
  'cloudRangesEnabled'
) as HTMLInputElement
export const dnsblEnabledEl = document.getElementById('dnsblEnabled') as HTMLInputElement
export const rdapEnabledEl = document.getElementById('rdapEnabled') as HTMLInputElement
export const geoIpOnlineFallbackEl = document.getElementById(
  'geoIpOnlineFallback'
) as HTMLInputElement
export const maxmindLicenseKeyEl = document.getElementById('maxmindLicenseKey') as HTMLInputElement
export const btnDownloadGeolite = document.getElementById(
  'btn-download-geolite'
) as HTMLButtonElement
export const geoliteStatusEl = document.getElementById('geolite-status') as HTMLSpanElement
export const forensicBody = document.getElementById('forensic-body') as HTMLTableSectionElement

export const builderStepsEl = document.getElementById('builder-steps') as HTMLOListElement
export const builderDomainEl = document.getElementById('builder-domain') as HTMLInputElement
export const builderDomainStatusEl = document.getElementById(
  'builder-domain-status'
) as HTMLParagraphElement
export const builderPolicyEl = document.getElementById('builder-policy') as HTMLSelectElement
export const builderSpEl = document.getElementById('builder-sp') as HTMLSelectElement
export const builderPctEl = document.getElementById('builder-pct') as HTMLInputElement
export const builderAdkimEl = document.getElementById('builder-adkim') as HTMLSelectElement
export const builderAspfEl = document.getElementById('builder-aspf') as HTMLSelectElement
export const builderRuaEl = document.getElementById('builder-rua') as HTMLInputElement
export const builderRufEl = document.getElementById('builder-ruf') as HTMLInputElement
export const builderResultEl = document.getElementById('builder-result') as HTMLDivElement
export const builderLiveEl = document.getElementById('builder-live') as HTMLDivElement
export const builderFooterHintEl = document.getElementById(
  'builder-footer-hint'
) as HTMLParagraphElement
export const btnBuilderBack = document.getElementById('btn-builder-back') as HTMLButtonElement
export const btnBuilderNext = document.getElementById('btn-builder-next') as HTMLButtonElement
export const btnBuilderLoadDns = document.getElementById(
  'btn-builder-load-dns'
) as HTMLButtonElement

export const spfBuilderDialog = document.getElementById('spf-builder-dialog') as HTMLDialogElement
export const spfBuilderStepsEl = document.getElementById('spf-builder-steps') as HTMLOListElement
export const spfBuilderDomainEl = document.getElementById('spf-builder-domain') as HTMLInputElement
export const spfBuilderDomainStatusEl = document.getElementById(
  'spf-builder-domain-status'
) as HTMLParagraphElement
export const spfBuilderIncludesEl = document.getElementById(
  'spf-builder-includes'
) as HTMLTextAreaElement
export const spfBuilderIp4El = document.getElementById('spf-builder-ip4') as HTMLTextAreaElement
export const spfBuilderIp6El = document.getElementById('spf-builder-ip6') as HTMLTextAreaElement
export const spfBuilderUseAEl = document.getElementById('spf-builder-use-a') as HTMLInputElement
export const spfBuilderUseMxEl = document.getElementById('spf-builder-use-mx') as HTMLInputElement
export const spfBuilderAllEl = document.getElementById('spf-builder-all') as HTMLSelectElement
export const spfBuilderResultEl = document.getElementById('spf-builder-result') as HTMLDivElement
export const spfBuilderLiveEl = document.getElementById('spf-builder-live') as HTMLDivElement
export const spfBuilderExpandEl = document.getElementById('spf-builder-expand') as HTMLDivElement
export const spfBuilderFooterHintEl = document.getElementById(
  'spf-builder-footer-hint'
) as HTMLParagraphElement
export const btnCloseSpfBuilder = document.getElementById(
  'btn-close-spf-builder'
) as HTMLButtonElement
export const btnSpfBuilderBack = document.getElementById(
  'btn-spf-builder-back'
) as HTMLButtonElement
export const btnSpfBuilderNext = document.getElementById(
  'btn-spf-builder-next'
) as HTMLButtonElement

export const tlsrptBuilderDialog = document.getElementById(
  'tlsrpt-builder-dialog'
) as HTMLDialogElement
export const tlsrptBuilderStepsEl = document.getElementById(
  'tlsrpt-builder-steps'
) as HTMLOListElement
export const tlsrptBuilderDomainEl = document.getElementById(
  'tlsrpt-builder-domain'
) as HTMLInputElement
export const tlsrptBuilderDomainStatusEl = document.getElementById(
  'tlsrpt-builder-domain-status'
) as HTMLParagraphElement
export const tlsrptBuilderRuaEl = document.getElementById('tlsrpt-builder-rua') as HTMLInputElement
export const tlsrptBuilderResultEl = document.getElementById(
  'tlsrpt-builder-result'
) as HTMLDivElement
export const tlsrptBuilderLiveEl = document.getElementById('tlsrpt-builder-live') as HTMLDivElement
export const tlsrptBuilderFooterHintEl = document.getElementById(
  'tlsrpt-builder-footer-hint'
) as HTMLParagraphElement
export const btnCloseTlsrptBuilder = document.getElementById(
  'btn-close-tlsrpt-builder'
) as HTMLButtonElement
export const btnTlsrptBuilderBack = document.getElementById(
  'btn-tlsrpt-builder-back'
) as HTMLButtonElement
export const btnTlsrptBuilderNext = document.getElementById(
  'btn-tlsrpt-builder-next'
) as HTMLButtonElement

export const mtaStsBuilderDialog = document.getElementById(
  'mta-sts-builder-dialog'
) as HTMLDialogElement
export const mtaStsBuilderStepsEl = document.getElementById(
  'mta-sts-builder-steps'
) as HTMLOListElement
export const mtaStsBuilderDomainEl = document.getElementById(
  'mta-sts-builder-domain'
) as HTMLInputElement
export const mtaStsBuilderDomainStatusEl = document.getElementById(
  'mta-sts-builder-domain-status'
) as HTMLParagraphElement
export const mtaStsBuilderModeEl = document.getElementById(
  'mta-sts-builder-mode'
) as HTMLSelectElement
export const mtaStsBuilderMaxAgeEl = document.getElementById(
  'mta-sts-builder-max-age'
) as HTMLInputElement
export const mtaStsBuilderMxEl = document.getElementById(
  'mta-sts-builder-mx'
) as HTMLTextAreaElement
export const mtaStsBuilderRenewIdEl = document.getElementById(
  'mta-sts-builder-renew-id'
) as HTMLInputElement
export const mtaStsBuilderResultEl = document.getElementById(
  'mta-sts-builder-result'
) as HTMLDivElement
export const mtaStsBuilderLiveEl = document.getElementById('mta-sts-builder-live') as HTMLDivElement
export const mtaStsBuilderFooterHintEl = document.getElementById(
  'mta-sts-builder-footer-hint'
) as HTMLParagraphElement
export const btnCloseMtaStsBuilder = document.getElementById(
  'btn-close-mta-sts-builder'
) as HTMLButtonElement
export const btnMtaStsBuilderBack = document.getElementById(
  'btn-mta-sts-builder-back'
) as HTMLButtonElement
export const btnMtaStsBuilderNext = document.getElementById(
  'btn-mta-sts-builder-next'
) as HTMLButtonElement
