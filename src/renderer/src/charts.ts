import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart,
  DoughnutController,
  BarController,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
  Filler,
  type ActiveElement,
  type ChartEvent
} from 'chart.js'
import { t } from '../../shared/i18n'
import type { AlignmentBreakdown, NamedBucket } from '../../shared/types'

Chart.register(
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  DoughnutController,
  BarController,
  LineController,
  LineElement,
  PointElement,
  Legend,
  Tooltip,
  Filler
)

function cssVar(name: string, fallback: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return value || fallback
}

function hexToRgba(hex: string, alpha: number): string {
  const raw = hex.replace('#', '')
  if (raw.length !== 6) return hex
  const n = Number.parseInt(raw, 16)
  if (!Number.isFinite(n)) return hex
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`
}

type ThemeColors = {
  ok: string
  bad: string
  other: string
  warn: string
  accent: string
  muted: string
  line: string
}

function themeColors(): ThemeColors {
  return {
    ok: cssVar('--ok', '#1f7a45'),
    bad: cssVar('--bad', '#b33a2b'),
    other: cssVar('--other', '#8a93a3'),
    warn: cssVar('--warn', '#b57b12'),
    accent: cssVar('--accent', '#1f6f8b'),
    muted: cssVar('--muted', '#5b6778'),
    line: cssVar('--line', '#d5dbe3')
  }
}

function dispositionColor(name: string, colors: ThemeColors): string {
  switch (name.toLowerCase()) {
    case 'none':
      return colors.accent
    case 'quarantine':
      return colors.warn
    case 'reject':
      return colors.bad
    default:
      return colors.other
  }
}

function createDoughnut(id: string): Chart<'doughnut'> {
  return new Chart(document.getElementById(id) as HTMLCanvasElement, {
    type: 'doughnut',
    data: {
      labels: ['Pass', 'Fail', 'Sonstige'],
      datasets: [
        {
          data: [0, 0, 0],
          backgroundColor: [themeColors().ok, themeColors().bad, themeColors().other],
          borderWidth: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom' }
      }
    }
  })
}

export const chartDmarc = createDoughnut('chart-dmarc')
export const chartSpf = createDoughnut('chart-spf')
export const chartDkim = createDoughnut('chart-dkim')
export const chartDisposition = new Chart(
  document.getElementById('chart-disposition') as HTMLCanvasElement,
  {
    type: 'doughnut',
    data: {
      labels: [] as string[],
      datasets: [{ data: [] as number[], backgroundColor: [] as string[], borderWidth: 0 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom' } }
    }
  }
)

let onVolumeDayClick: ((date: string) => void) | null = null

export function setVolumeDayClickHandler(fn: (date: string) => void): void {
  onVolumeDayClick = fn
}

export const chartVolume = new Chart(document.getElementById('chart-volume') as HTMLCanvasElement, {
  data: {
    labels: [] as string[],
    datasets: [
      {
        type: 'bar',
        label: 'Pass',
        data: [] as number[],
        backgroundColor: hexToRgba(themeColors().ok, 0.85),
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'bar',
        label: 'Fail',
        data: [] as number[],
        backgroundColor: hexToRgba(themeColors().bad, 0.8),
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'line',
        label: 'Pass-Rate %',
        data: [] as number[],
        borderColor: themeColors().accent,
        backgroundColor: hexToRgba(themeColors().accent, 0.12),
        tension: 0.25,
        fill: false,
        yAxisID: 'y1',
        pointRadius: 2,
        borderWidth: 2
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: { stacked: true, grid: { display: false } },
      y: { stacked: true, beginAtZero: true, position: 'left' },
      y1: {
        beginAtZero: true,
        max: 100,
        position: 'right',
        grid: { drawOnChartArea: false },
        ticks: { callback: (v) => `${v}%` }
      }
    },
    plugins: {
      legend: { position: 'bottom' }
    },
    onClick: (_event: ChartEvent, elements: ActiveElement[], chart) => {
      if (!elements.length) return
      const label = chart.data.labels?.[elements[0].index]
      if (typeof label === 'string') onVolumeDayClick?.(label)
    },
    onHover: (event: ChartEvent, elements: ActiveElement[]) => {
      const el = event.native?.target
      if (el instanceof HTMLElement) el.style.cursor = elements.length ? 'pointer' : 'default'
    }
  }
})

export function setAlignmentChart(chart: Chart<'doughnut'>, data: AlignmentBreakdown): void {
  chart.data.datasets[0].data = [data.pass, data.fail, data.other]
  chart.update()
}

export function setDispositionChart(buckets: NamedBucket[]): void {
  chartDisposition.data.labels = buckets.map((b) => b.name)
  chartDisposition.data.datasets[0].data = buckets.map((b) => b.count)
  const colors = themeColors()
  ;(chartDisposition.data.datasets[0].backgroundColor as string[]) = buckets.map((b) =>
    dispositionColor(b.name, colors)
  )
  chartDisposition.update()
}

export function applyChartTheme(): void {
  const colors = themeColors()
  Chart.defaults.color = colors.muted
  Chart.defaults.borderColor = colors.line
  const doughnut = [colors.ok, colors.bad, colors.other]
  for (const chart of [chartDmarc, chartSpf, chartDkim]) {
    chart.data.datasets[0].backgroundColor = doughnut
    if (chart.options.plugins?.legend?.labels) {
      chart.options.plugins.legend.labels.color = colors.muted
    }
    chart.update('none')
  }
  const labels = (chartDisposition.data.labels ?? []) as string[]
  chartDisposition.data.datasets[0].backgroundColor = labels.map((name) =>
    dispositionColor(name, colors)
  )
  if (chartDisposition.options.plugins?.legend?.labels) {
    chartDisposition.options.plugins.legend.labels.color = colors.muted
  }
  chartDisposition.update('none')
  chartVolume.data.datasets[0].backgroundColor = hexToRgba(colors.ok, 0.85)
  chartVolume.data.datasets[1].backgroundColor = hexToRgba(colors.bad, 0.8)
  chartVolume.data.datasets[2].borderColor = colors.accent
  chartVolume.data.datasets[2].backgroundColor = hexToRgba(colors.accent, 0.12)
  const scales = chartVolume.options.scales
  if (scales) {
    for (const key of ['x', 'y', 'y1'] as const) {
      const scale = scales[key]
      if (!scale || typeof scale !== 'object') continue
      if (scale.ticks) scale.ticks.color = colors.muted
      if (scale.grid && 'color' in scale.grid) {
        scale.grid.color = hexToRgba(colors.line, 0.55)
      }
    }
  }
  if (chartVolume.options.plugins?.legend?.labels) {
    chartVolume.options.plugins.legend.labels.color = colors.muted
  }
  chartVolume.update('none')
}

export function updateChartLocaleLabels(): void {
  const doughnutLabels = [t('chart.pass'), t('chart.fail'), t('chart.other')]
  for (const chart of [chartDmarc, chartSpf, chartDkim]) {
    chart.data.labels = doughnutLabels
    chart.update()
  }
  chartVolume.data.datasets[0].label = t('chart.pass')
  chartVolume.data.datasets[1].label = t('chart.fail')
  chartVolume.data.datasets[2].label = t('chart.passRate')
  const volumeCanvas = document.getElementById('chart-volume')
  if (volumeCanvas) volumeCanvas.title = t('filter.clickToFilter')
  chartVolume.update()
}

export function clearVolumeChart(): void {
  chartVolume.data.labels = []
  chartVolume.data.datasets[0].data = []
  chartVolume.data.datasets[1].data = []
  chartVolume.data.datasets[2].data = []
  chartVolume.update()
}

export function setVolumeChart(
  labels: string[],
  passing: number[],
  failing: number[],
  passRate: number[]
): void {
  chartVolume.data.labels = labels
  chartVolume.data.datasets[0].data = passing
  chartVolume.data.datasets[1].data = failing
  chartVolume.data.datasets[2].data = passRate
  chartVolume.update()
}
