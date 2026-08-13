import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { t } from '../../shared/i18n'
import type { NamedBucket } from '../../shared/types'
import { ipMapEl, ipMapEmptyEl } from './dom'
import { escapeHtml } from './format'
import { state } from './state'

type IpMapPoint = {
  ip: string
  lat: number
  lon: number
  count: number
  passing: number
  failing: number
  passRate: number
  label: string | null
}

let map: L.Map | null = null
let layer: L.LayerGroup | null = null
let onFilterIp: ((ip: string) => void) | null = null

function cssVar(name: string, fallback: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return value || fallback
}

function statusColor(passRate: number, failing: number): string {
  if (failing === 0 && passRate >= 98) return cssVar('--ok', '#1f7a45')
  if (passRate >= 90) return cssVar('--warn', '#b57b12')
  return cssVar('--bad', '#b33a2b')
}

export function invalidateIpMapSize(): void {
  if (!map) return
  requestAnimationFrame(() => map?.invalidateSize())
}

function ensureMap(): L.Map | null {
  if (!ipMapEl) return null
  if (map) return map

  map = L.map(ipMapEl, {
    zoomControl: true,
    attributionControl: true
  }).setView([20, 0], 2)

  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 18,
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
  }).addTo(map)

  layer = L.layerGroup().addTo(map)
  return map
}

function collectPoints(rows: NamedBucket[]): IpMapPoint[] {
  const points: IpMapPoint[] = []
  for (const row of rows) {
    const info = state.ipLabelCache.get(row.name)
    if (info?.lat == null || info?.lon == null) continue
    points.push({
      ip: row.name,
      lat: info.lat,
      lon: info.lon,
      count: row.count,
      passing: row.passing,
      failing: row.failing,
      passRate: row.passRate,
      label: info.city || info.country || info.ptr || row.label || null
    })
  }
  return points
}

export function setIpMapFilterHandler(fn: (ip: string) => void): void {
  onFilterIp = fn
}

/** Render source-IP markers on an OpenStreetMap basemap. */
export function renderIpMap(rows: NamedBucket[]): void {
  if (!ipMapEl || !ipMapEmptyEl) return

  const points = collectPoints(rows)
  ipMapEmptyEl.classList.toggle('hidden', points.length > 0 || rows.length === 0)
  if (rows.length === 0) {
    ipMapEmptyEl.textContent = t('ipMap.noSources')
    ipMapEmptyEl.classList.remove('hidden')
  } else if (points.length === 0) {
    ipMapEmptyEl.textContent = t('ipMap.empty')
    ipMapEmptyEl.classList.remove('hidden')
  }

  const m = ensureMap()
  if (!m || !layer) return

  layer.clearLayers()
  if (points.length === 0) {
    m.setView([20, 0], 2)
    // Leaflet needs a kick when the container was empty/hidden initially.
    requestAnimationFrame(() => m.invalidateSize())
    return
  }

  const bounds: L.LatLngExpression[] = []
  for (const p of points) {
    const color = statusColor(p.passRate, p.failing)
    const marker = L.circleMarker([p.lat, p.lon], {
      radius: Math.max(7, Math.min(16, 6 + Math.log2(p.count + 1) * 2)),
      color,
      weight: 2,
      fillColor: color,
      fillOpacity: 0.72
    })
    const place = p.label ? `<br />${escapeHtml(p.label)}` : ''
    marker.bindPopup(
      `<strong class="mono">${escapeHtml(p.ip)}</strong>${place}<br />` +
        `${escapeHtml(t('ipMap.passRate', { rate: p.passRate.toFixed(1) }))} · ` +
        `${escapeHtml(t('ipMap.msgs', { count: String(p.count) }))}`
    )
    marker.on('click', () => onFilterIp?.(p.ip))
    marker.addTo(layer)
    bounds.push([p.lat, p.lon])
  }

  requestAnimationFrame(() => {
    m.invalidateSize()
    if (bounds.length === 1) m.setView(bounds[0]!, 6)
    else m.fitBounds(L.latLngBounds(bounds), { padding: [28, 28], maxZoom: 8 })
  })
}
