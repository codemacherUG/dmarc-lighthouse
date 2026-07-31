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
  Filler
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

const PASS = '#1f7a45'
const FAIL = '#b33a2b'
const OTHER = '#8a93a3'
const VOLUME_PASS = 'rgba(31, 122, 69, 0.85)'
const VOLUME_FAIL = 'rgba(179, 58, 43, 0.8)'
const RATE_LINE = '#1f6f8b'

const DISPOSITION_COLORS: Record<string, string> = {
  none: '#1f6f8b',
  quarantine: '#b57b12',
  reject: '#b33a2b'
}

function createDoughnut(id: string): Chart<'doughnut'> {
  return new Chart(document.getElementById(id) as HTMLCanvasElement, {
    type: 'doughnut',
    data: {
      labels: ['Pass', 'Fail', 'Sonstige'],
      datasets: [
        {
          data: [0, 0, 0],
          backgroundColor: [PASS, FAIL, OTHER],
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
export const chartVolume = new Chart(document.getElementById('chart-volume') as HTMLCanvasElement, {
  data: {
    labels: [] as string[],
    datasets: [
      {
        type: 'bar',
        label: 'Pass',
        data: [] as number[],
        backgroundColor: VOLUME_PASS,
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'bar',
        label: 'Fail',
        data: [] as number[],
        backgroundColor: VOLUME_FAIL,
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'line',
        label: 'Pass-Rate %',
        data: [] as number[],
        borderColor: RATE_LINE,
        backgroundColor: 'rgba(31, 111, 139, 0.12)',
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
  ;(chartDisposition.data.datasets[0].backgroundColor as string[]) = buckets.map(
    (b) => DISPOSITION_COLORS[b.name.toLowerCase()] ?? OTHER
  )
  chartDisposition.update()
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
