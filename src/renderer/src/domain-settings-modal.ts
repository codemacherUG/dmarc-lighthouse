import { normalizeDkimSelector } from '../../shared/dkim-selector'
import { t, type MessageKey } from '../../shared/i18n'
import { parseDomainList } from '../../shared/sending-services'
import type { DomainDkimSelector, SendingService, SendingServiceStatus } from '../../shared/types'
import { renderDnsHistory } from './dns-history-view'
import {
  btnCloseDnsHistory,
  btnCloseDomainDkim,
  btnDnsHistoryCheck,
  btnDnsHistoryClose,
  btnDomainDkimAdd,
  btnDomainDkimSave,
  btnDomainSenderCancel,
  btnDomainSenderSave,
  dnsDialog,
  dnsDomainEl,
  dnsForm,
  dnsHistoryBody,
  dnsHistoryDialog,
  dnsHistoryTitle,
  domainDkimDialog,
  domainDkimInput,
  domainDkimList,
  domainDkimStatus,
  domainDkimTabButton,
  domainDkimTabPanel,
  domainDkimTitle,
  domainSenderAsn,
  domainSenderCidr,
  domainSenderForm,
  domainSenderNote,
  domainSenderProvider,
  domainSendersList,
  domainSendersStatus,
  domainSendersTabButton,
  domainSendersTabPanel,
  domainSenderStatus,
  domainSenderTeam
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

let editingDkimDomain = ''
let editingDkimSelectors: DomainDkimSelector[] = []
let dnsHistoryDomain = ''
let dnsHistoryRequest = 0
let editingDomainSendingServiceId: string | null = null
let editingDomainSendingServiceCard: HTMLElement | null = null
let editingDomainSenderForm: HTMLFormElement | null = null
let domainSenderSavedHandler: ((service: SendingService) => Promise<void>) | null = null
let domainSendingServices: SendingService[] = []

let onSendersChangedCallback: (() => void) | null = null
let onDkimSavedCallback: (() => void) | null = null

export function setDomainSettingsCallbacks(callbacks: {
  onSendersChanged: () => void
  onDkimSaved: () => void
}): void {
  onSendersChangedCallback = callbacks.onSendersChanged
  onDkimSavedCallback = callbacks.onDkimSaved
}

export async function openDnsHistory(domain: string): Promise<void> {
  const request = ++dnsHistoryRequest
  dnsHistoryDomain = domain
  dnsHistoryTitle.textContent = t('dns.historyDomainTitle', { domain })
  dnsHistoryBody.innerHTML = `<p class="muted">${escapeHtml(t('dns.historyLoading'))}</p>`
  dnsHistoryDialog.showModal()
  try {
    const history = await window.api.dnsHistory(domain)
    if (request !== dnsHistoryRequest) return
    dnsHistoryBody.innerHTML =
      renderDnsHistory(history, { changesOpen: true }) ||
      `<p class="muted">${escapeHtml(t('dns.historyEmpty'))}</p>`
  } catch (error) {
    if (request !== dnsHistoryRequest) return
    dnsHistoryBody.innerHTML = `<p class="fail">${escapeHtml(
      t('dns.historyLoadError', {
        message: error instanceof Error ? error.message : String(error)
      })
    )}</p>`
  }
}

export function showDomainSettingsTab(tab: 'dkim' | 'senders'): void {
  const dkimActive = tab === 'dkim'
  domainDkimTabButton.classList.toggle('active', dkimActive)
  domainDkimTabButton.setAttribute('aria-selected', String(dkimActive))
  domainDkimTabPanel.classList.toggle('hidden', !dkimActive)
  domainSendersTabButton.classList.toggle('active', !dkimActive)
  domainSendersTabButton.setAttribute('aria-selected', String(!dkimActive))
  domainSendersTabPanel.classList.toggle('hidden', dkimActive)
}

function renderDomainDkimSelectors(): void {
  if (editingDkimSelectors.length === 0) {
    domainDkimList.innerHTML = `<p class="muted">${escapeHtml(t('health.dkimEmpty'))}</p>`
    return
  }
  domainDkimList.innerHTML = editingDkimSelectors
    .map(
      ({ selector, enabled }) => `
      <label class="domain-dkim-row">
        <input type="checkbox" data-selector="${escapeHtml(selector)}" ${enabled ? 'checked' : ''} />
        <code>${escapeHtml(selector)}</code>
        <span class="muted">${escapeHtml(t(enabled ? 'health.dkimEnabled' : 'health.dkimDisabled'))}</span>
      </label>`
    )
    .join('')
}

function resetDomainSendingServiceForm(): void {
  editingDomainSendingServiceCard?.classList.remove('is-editing')
  const toggle =
    editingDomainSendingServiceCard?.querySelector<HTMLButtonElement>('[data-sender-edit]')
  toggle?.setAttribute('aria-expanded', 'false')
  if (toggle) {
    toggle.textContent = '▾'
    toggle.setAttribute('aria-label', t('health.sendingServicesExpand'))
    toggle.title = t('health.sendingServicesExpand')
    toggle.setAttribute('aria-controls', domainSenderForm.id)
  }
  editingDomainSenderForm?.remove()
  editingDomainSenderForm = null
  editingDomainSendingServiceCard = null
  editingDomainSendingServiceId = null
  domainSenderProvider.value = ''
  domainSenderCidr.value = ''
  domainSenderAsn.value = ''
  domainSenderStatus.value = 'known'
  domainSenderTeam.value = ''
  domainSenderNote.value = ''
  btnDomainSenderSave.textContent = t('sendingServices.add')
  btnDomainSenderCancel.classList.add('hidden')
}

function editDomainSendingService(service: SendingService, card: HTMLElement): void {
  resetDomainSendingServiceForm()
  editingDomainSendingServiceId = service.id
  editingDomainSendingServiceCard = card
  const form = domainSenderForm.cloneNode(true) as HTMLFormElement
  form.removeAttribute('id')
  form.id = `domain-sender-edit-form-${service.id}`
  form.dataset.serviceId = service.id
  form.classList.add('domain-sender-edit-form')
  form.querySelectorAll<HTMLElement>('[id]').forEach((element) => element.removeAttribute('id'))
  form.addEventListener('submit', (event) => {
    event.preventDefault()
    void persistDomainSendingService(form)
  })
  senderFormButton(form, '[data-sender-cancel]').addEventListener(
    'click',
    resetDomainSendingServiceForm
  )
  editingDomainSenderForm = form
  card.classList.add('is-editing')
  const toggle = card.querySelector<HTMLButtonElement>('[data-sender-edit]')
  toggle?.setAttribute('aria-expanded', 'true')
  if (toggle) {
    toggle.textContent = '▴'
    toggle.setAttribute('aria-label', t('health.sendingServicesCollapse'))
    toggle.title = t('health.sendingServicesCollapse')
    toggle.setAttribute('aria-controls', form.id)
  }
  card.append(form)
  senderFormField<HTMLInputElement>(form, 'provider').value = service.provider
  senderFormField<HTMLInputElement>(form, 'cidr').value = service.cidr ?? ''
  senderFormField<HTMLInputElement>(form, 'asn').value =
    service.asn != null ? String(service.asn) : ''
  senderFormField<HTMLSelectElement>(form, 'status').value = service.status
  senderFormField<HTMLInputElement>(form, 'team').value = service.team ?? ''
  senderFormField<HTMLInputElement>(form, 'note').value = service.note ?? ''
  senderFormButton(form, '[data-sender-save]').textContent = t('sendingServices.saveChanges')
  senderFormButton(form, '[data-sender-cancel]').classList.remove('hidden')
  senderFormField<HTMLInputElement>(form, 'provider').focus({ preventScroll: true })
}

function senderFormField<T extends HTMLInputElement | HTMLSelectElement>(
  form: HTMLFormElement,
  field: string
): T {
  const element = form.querySelector<T>(`[name="${field}"]`)
  if (!element) throw new Error(`Missing sending-service form field: ${field}`)
  return element
}

function senderFormButton<T extends HTMLButtonElement>(form: HTMLFormElement, selector: string): T {
  const button = form.querySelector<T>(selector)
  if (!button) throw new Error(`Missing sending-service form button: ${selector}`)
  return button
}

function renderDomainSendingServices(): void {
  const domain = editingDkimDomain.toLowerCase()
  const matches = domainSendingServices.filter((service) => {
    const domains = parseDomainList(service.domain)
    return domains.length === 0 || domains.includes(domain)
  })
  if (matches.length === 0) {
    domainSendersList.innerHTML = `<p class="muted">${escapeHtml(t('health.sendingServicesEmpty'))}</p>`
    return
  }

  const statusKey: Record<SendingServiceStatus, MessageKey> = {
    known: 'sendingServices.status.known',
    unknown: 'sendingServices.status.unknown',
    investigate: 'sendingServices.status.investigate',
    retired: 'sendingServices.status.retired'
  }
  domainSendersList.innerHTML = matches
    .map((service) => {
      const domains = parseDomainList(service.domain)
      const editable = domains.length === 1 && domains[0] === domain
      const scope = [service.cidr, service.asn != null ? `AS${service.asn}` : null]
        .filter(Boolean)
        .join(' · ')
      return `
        <article class="domain-sender-card">
          <div class="domain-sender-card-header">
          <div class="domain-sender-card-main">
            <strong>${escapeHtml(service.provider)}</strong>
            <span class="domain-sender-status">${escapeHtml(t(statusKey[service.status]))}</span>
            ${scope ? `<span class="domain-sender-scope">${escapeHtml(scope)}</span>` : ''}
            ${service.team ? `<span>${escapeHtml(service.team)}</span>` : ''}
            ${service.note ? `<span class="domain-sender-note">${escapeHtml(service.note)}</span>` : ''}
          </div>
          ${
            editable
              ? `<div class="domain-sender-card-actions">
                  <button type="button" class="btn danger" data-sender-delete="${escapeHtml(service.id)}">${escapeHtml(t('health.sendingServicesDelete'))}</button>
                  <button type="button" class="btn secondary domain-sender-accordion-toggle" data-sender-edit="${escapeHtml(service.id)}" aria-label="${escapeHtml(t('health.sendingServicesExpand'))}" title="${escapeHtml(t('health.sendingServicesExpand'))}" aria-expanded="false" aria-controls="domain-sender-form">▾</button>
                </div>`
              : `<span class="domain-sender-shared">${escapeHtml(t('health.sendingServicesShared'))}</span>`
          }
          </div>
        </article>`
    })
    .join('')

  domainSendersList.querySelectorAll<HTMLButtonElement>('[data-sender-edit]').forEach((button) => {
    button.addEventListener('click', () => {
      const service = matches.find((item) => item.id === button.dataset.senderEdit)
      const card = button.closest<HTMLElement>('.domain-sender-card')
      if (!service || !card) return
      if (editingDomainSendingServiceCard === card) {
        resetDomainSendingServiceForm()
      } else {
        editDomainSendingService(service, card)
      }
    })
  })
  domainSendersList
    .querySelectorAll<HTMLButtonElement>('[data-sender-delete]')
    .forEach((button) => {
      button.addEventListener('click', () => {
        void deleteDomainSendingService(button.dataset.senderDelete ?? '')
      })
    })
}

async function loadDomainSendingServices(): Promise<void> {
  try {
    domainSendingServices = await window.api.listSendingServices()
    renderDomainSendingServices()
    domainSendersStatus.textContent = ''
  } catch (error) {
    domainSendersStatus.textContent = t('health.sendingServicesLoadError', {
      message: error instanceof Error ? error.message : String(error)
    })
    domainSendersList.innerHTML = ''
  }
}

async function persistDomainSendingService(form: HTMLFormElement): Promise<void> {
  const providerField = senderFormField<HTMLInputElement>(form, 'provider')
  const cidrField = senderFormField<HTMLInputElement>(form, 'cidr')
  const asnField = senderFormField<HTMLInputElement>(form, 'asn')
  const statusField = senderFormField<HTMLSelectElement>(form, 'status')
  const teamField = senderFormField<HTMLInputElement>(form, 'team')
  const noteField = senderFormField<HTMLInputElement>(form, 'note')
  const saveButton = senderFormButton<HTMLButtonElement>(form, '[data-sender-save]')
  const provider = providerField.value.trim()
  if (!provider) {
    domainSendersStatus.textContent = t('sendingServices.providerRequired')
    providerField.focus()
    return
  }
  const asnRaw = asnField.value.trim()
  const asn = asnRaw ? Number(asnRaw) : null
  if (asn != null && (!Number.isInteger(asn) || asn < 0)) {
    domainSendersStatus.textContent = t('health.sendingServicesInvalidAsn')
    asnField.focus()
    return
  }
  const domain = editingDkimDomain
  saveButton.disabled = true
  domainSendersStatus.textContent = ''
  try {
    const savedService = await window.api.saveSendingService({
      id: form.dataset.serviceId,
      provider,
      domain,
      cidr: cidrField.value.trim() || null,
      asn,
      status: statusField.value as SendingServiceStatus,
      team: teamField.value.trim() || null,
      note: noteField.value.trim() || null
    })
    const isNewService = !form.dataset.serviceId
    const afterSave = isNewService ? domainSenderSavedHandler : null
    if (isNewService) domainSenderSavedHandler = null
    resetDomainSendingServiceForm()
    domainSendingServices = await window.api.listSendingServices()
    renderDomainSendingServices()
    domainSendersStatus.textContent = t('sendingServices.saved')
    state.sendingServices = domainSendingServices
    await afterSave?.(savedService)
    onSendersChangedCallback?.()
  } catch (error) {
    domainSendersStatus.textContent = error instanceof Error ? error.message : String(error)
  } finally {
    saveButton.disabled = false
  }
}

async function deleteDomainSendingService(id: string): Promise<void> {
  if (!id) return
  try {
    domainSendingServices = await window.api.deleteSendingService(id)
    if (editingDomainSendingServiceId === id) resetDomainSendingServiceForm()
    renderDomainSendingServices()
    domainSendersStatus.textContent = t('sendingServices.deleted')
    state.sendingServices = domainSendingServices
    onSendersChangedCallback?.()
  } catch (error) {
    domainSendersStatus.textContent = error instanceof Error ? error.message : String(error)
  }
}

export async function openDomainDkimSettings(
  domain: string,
  options?: {
    senderDraft?: {
      provider?: string
      cidr?: string
      asn?: number | null
      status?: SendingServiceStatus
      note?: string
    }
    onSenderSaved?: (service: SendingService) => Promise<void>
    initialTab?: 'dkim' | 'senders'
    demoData?: {
      selectors: DomainDkimSelector[]
      senderServices: SendingService[]
    }
  }
): Promise<void> {
  editingDkimDomain = domain
  editingDkimSelectors = []
  domainSendingServices = []
  resetDomainSendingServiceForm()
  domainSenderSavedHandler = options?.onSenderSaved ?? null
  domainDkimTitle.textContent = `${t('health.domainSettingsTitle')} — ${domain}`
  showDomainSettingsTab(options?.senderDraft ? 'senders' : (options?.initialTab ?? 'dkim'))
  if (options?.senderDraft) {
    senderFormField<HTMLInputElement>(domainSenderForm, 'provider').value =
      options.senderDraft.provider ?? ''
    senderFormField<HTMLInputElement>(domainSenderForm, 'cidr').value =
      options.senderDraft.cidr ?? ''
    senderFormField<HTMLInputElement>(domainSenderForm, 'asn').value =
      options.senderDraft.asn != null ? String(options.senderDraft.asn) : ''
    senderFormField<HTMLSelectElement>(domainSenderForm, 'status').value =
      options.senderDraft.status ?? 'known'
    senderFormField<HTMLInputElement>(domainSenderForm, 'team').value = ''
    senderFormField<HTMLInputElement>(domainSenderForm, 'note').value =
      options.senderDraft.note ?? ''
  }
  domainDkimList.innerHTML = `<p class="muted">${escapeHtml(t('health.loading'))}</p>`
  domainDkimStatus.textContent = ''
  domainDkimInput.value = ''
  domainSendersStatus.textContent = ''
  domainSendersList.innerHTML = `<p class="muted">${escapeHtml(t('health.loading'))}</p>`
  btnDomainDkimAdd.disabled = true
  btnDomainDkimSave.disabled = true
  domainDkimDialog.showModal()
  try {
    const demoData = options?.demoData
    const selectorsPromise = demoData
      ? Promise.resolve(demoData.selectors)
      : window.api.getDomainDkimSelectors(domain)
    const servicesPromise = demoData
      ? Promise.resolve().then(() => {
          domainSendingServices = demoData.senderServices
          renderDomainSendingServices()
        })
      : loadDomainSendingServices()
    const [selectors] = await Promise.all([selectorsPromise, servicesPromise])
    if (editingDkimDomain !== domain) return
    editingDkimSelectors = selectors
    renderDomainDkimSelectors()
    btnDomainDkimAdd.disabled = false
    btnDomainDkimSave.disabled = false
  } catch (error) {
    domainDkimStatus.textContent = t('health.dkimLoadError', {
      message: error instanceof Error ? error.message : String(error)
    })
    domainDkimList.innerHTML = ''
  }
}

function addDomainDkimSelector(): void {
  const selector = normalizeDkimSelector(domainDkimInput.value)
  if (!selector) {
    domainDkimStatus.textContent = t('health.dkimInvalid')
    return
  }
  if (editingDkimSelectors.some((item) => item.selector === selector)) {
    domainDkimStatus.textContent = t('health.dkimAlreadyExists')
    return
  }
  editingDkimSelectors.push({ selector, enabled: true })
  editingDkimSelectors.sort((a, b) => a.selector.localeCompare(b.selector))
  domainDkimInput.value = ''
  domainDkimStatus.textContent = ''
  renderDomainDkimSelectors()
}

export function openDomainSettingsScreenshotDemo(): Promise<void> {
  return openDomainDkimSettings('example.com', {
    initialTab: 'senders',
    demoData: {
      selectors: [
        { selector: 'selector1', enabled: true },
        { selector: 'selector2', enabled: true }
      ],
      senderServices: [
        {
          id: 'screenshot-m365',
          provider: 'Microsoft 365',
          domain: 'example.com',
          cidr: '40.92.0.0/14',
          asn: 8075,
          status: 'known',
          team: 'IT',
          note: 'Primary mail platform',
          createdAt: '',
          updatedAt: ''
        },
        {
          id: 'screenshot-sendgrid',
          provider: 'SendGrid',
          domain: 'example.com',
          cidr: null,
          asn: null,
          status: 'investigate',
          team: 'Marketing',
          note: 'Newsletter sender',
          createdAt: '',
          updatedAt: ''
        }
      ]
    }
  }).then(() => {
    const editButton = domainSendersList.querySelector<HTMLButtonElement>(
      '[data-sender-edit="screenshot-m365"]'
    )
    editButton?.click()
  })
}

export function initDomainSettingsModalEvents(): void {
  btnCloseDnsHistory.addEventListener('click', () => dnsHistoryDialog.close())
  btnDnsHistoryClose.addEventListener('click', () => dnsHistoryDialog.close())
  btnDnsHistoryCheck?.addEventListener('click', () => {
    const domain = dnsHistoryDomain.trim()
    dnsHistoryDialog.close()
    if (domain) {
      dnsDomainEl.value = domain
    }
    if (!dnsDialog.open) dnsDialog.showModal()
    if (domain) {
      dnsForm.requestSubmit()
    }
  })
  btnCloseDomainDkim.addEventListener('click', () => domainDkimDialog.close())
  domainDkimTabButton.addEventListener('click', () => showDomainSettingsTab('dkim'))
  domainSendersTabButton.addEventListener('click', () => showDomainSettingsTab('senders'))
  domainSenderForm.addEventListener('submit', (event) => {
    event.preventDefault()
    void persistDomainSendingService(domainSenderForm)
  })
  btnDomainSenderCancel.addEventListener('click', resetDomainSendingServiceForm)
  btnDomainDkimAdd.addEventListener('click', addDomainDkimSelector)
  domainDkimInput.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return
    event.preventDefault()
    addDomainDkimSelector()
  })
  domainDkimList.addEventListener('change', (event) => {
    if (!(event.target instanceof HTMLInputElement) || event.target.type !== 'checkbox') return
    const selector = event.target.dataset.selector
    const entry = editingDkimSelectors.find((item) => item.selector === selector)
    if (entry) {
      entry.enabled = event.target.checked
      renderDomainDkimSelectors()
    }
  })
  btnDomainDkimSave.addEventListener('click', async () => {
    if (!editingDkimDomain) return
    btnDomainDkimSave.disabled = true
    domainDkimStatus.textContent = ''
    try {
      await window.api.saveDomainDkimSelectors(editingDkimDomain, editingDkimSelectors)
      domainDkimDialog.close()
      onDkimSavedCallback?.()
    } catch (error) {
      domainDkimStatus.textContent = t('health.dkimSaveError', {
        message: error instanceof Error ? error.message : String(error)
      })
    } finally {
      btnDomainDkimSave.disabled = false
    }
  })
}
