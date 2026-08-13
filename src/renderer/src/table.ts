import { ipSortKey } from '../../shared/ipcidr'

export type SortDir = 'asc' | 'desc'

export interface SortState<K extends string = string> {
  key: K
  dir: SortDir
}

export interface SortColumn<K extends string> {
  /** Sort key, or null for a column that cannot be sorted (e.g. actions). */
  key: K | null
  /** Direction applied when this column is picked; defaults to ascending. */
  firstDir?: SortDir
}

/** Case-insensitive compare that orders embedded numbers naturally. */
export function compareText(a: string | null | undefined, b: string | null | undefined): number {
  return (a ?? '').localeCompare(b ?? '', undefined, { numeric: true, sensitivity: 'base' })
}

export function compareNumber(a: number, b: number): number {
  return a - b
}

/** Compare IPs numerically; non-IP values fall back to text order. */
export function compareIp(a: string, b: string): number {
  const ka = ipSortKey(a)
  const kb = ipSortKey(b)
  if (ka == null || kb == null) return compareText(a, b)
  return ka < kb ? -1 : ka > kb ? 1 : 0
}

/** Sort a copy of `rows` and apply the direction. */
export function sortRows<T, K extends string>(
  rows: readonly T[],
  state: SortState<K>,
  compare: (a: T, b: T, key: K) => number
): T[] {
  const factor = state.dir === 'asc' ? 1 : -1
  return [...rows].sort((a, b) => compare(a, b, state.key) * factor)
}

function syncHeaderState<K extends string>(
  headers: HTMLTableCellElement[],
  columns: Array<SortColumn<K>>,
  state: SortState<K>
): void {
  headers.forEach((th, index) => {
    const key = columns[index]?.key
    if (!key) return
    th.setAttribute(
      'aria-sort',
      key === state.key ? (state.dir === 'asc' ? 'ascending' : 'descending') : 'none'
    )
  })
}

/**
 * Make a table's header row sortable via mouse and keyboard.
 *
 * The caller owns `state`; this mutates it and then calls `onSort` to re-render.
 * The sort arrow comes from CSS on `aria-sort`, because `applyDomI18n` replaces
 * the header's text content on every locale change.
 */
export function initSortableHeader<K extends string>(config: {
  table: HTMLTableElement | null | undefined
  columns: Array<SortColumn<K>>
  state: SortState<K>
  onSort: () => void
}): void {
  const headRow = config.table?.tHead?.rows[0]
  if (!headRow) return
  const headers = [...headRow.cells]

  headers.forEach((th, index) => {
    const column = config.columns[index]
    if (!column?.key) return
    const key = column.key
    th.classList.add('sortable')
    th.tabIndex = 0

    const activate = (): void => {
      if (config.state.key === key) {
        config.state.dir = config.state.dir === 'asc' ? 'desc' : 'asc'
      } else {
        config.state.key = key
        config.state.dir = column.firstDir ?? 'asc'
      }
      syncHeaderState(headers, config.columns, config.state)
      config.onSort()
    }

    th.addEventListener('click', activate)
    th.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return
      event.preventDefault()
      activate()
    })
  })

  syncHeaderState(headers, config.columns, config.state)
}

function focusableRows(tbody: HTMLTableSectionElement): HTMLTableRowElement[] {
  return [...tbody.querySelectorAll<HTMLTableRowElement>('tr[tabindex]')]
}

/**
 * Keyboard support for clickable rows: Enter/Space activate, arrows move focus.
 * Delegated on the tbody so it survives re-rendering.
 */
export function enableRowKeyboardNav(tbody: HTMLTableSectionElement | null | undefined): void {
  if (!tbody) return
  tbody.addEventListener('keydown', (event) => {
    const target = event.target
    if (!(target instanceof HTMLElement)) return
    const row = target.closest('tr[tabindex]')
    if (!(row instanceof HTMLTableRowElement) || !tbody.contains(row)) return
    // Buttons inside the row keep their own key handling.
    if (target !== row && target.closest('button')) return

    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      row.click()
      return
    }

    const rows = focusableRows(tbody)
    const index = rows.indexOf(row)
    if (index < 0) return
    let next = -1
    if (event.key === 'ArrowDown') next = Math.min(rows.length - 1, index + 1)
    else if (event.key === 'ArrowUp') next = Math.max(0, index - 1)
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = rows.length - 1
    if (next < 0 || next === index) return
    event.preventDefault()
    rows[next]?.focus()
  })
}

export interface WindowedTable<T> {
  /** Replace the data set and render the visible window. */
  setRows(rows: readonly T[]): void
}

/** Nearest scrollable ancestor, used as the viewport for windowing. */
function findScroller(el: HTMLElement): HTMLElement | null {
  let cur = el.parentElement
  while (cur) {
    const overflowY = getComputedStyle(cur).overflowY
    if (overflowY === 'auto' || overflowY === 'scroll') return cur
    cur = cur.parentElement
  }
  return null
}

/**
 * Render only the rows near the viewport, padded by spacer rows so the scroll
 * height stays correct. Row heights must be uniform, which holds for the flat
 * report and forensic tables.
 */
export function createWindowedTable<T>(config: {
  body: HTMLTableSectionElement
  /** Column count for the spacer and empty rows. */
  columns: number
  /** Below this row count everything is rendered at once. */
  threshold?: number
  /** Extra rows kept above and below the viewport. */
  overscan?: number
  renderRow: (item: T) => HTMLTableRowElement
  renderEmpty: () => string
}): WindowedTable<T> {
  const { body, columns, renderRow, renderEmpty } = config
  const threshold = config.threshold ?? 60
  const overscan = config.overscan ?? 12
  const scroller = findScroller(body)

  let rows: readonly T[] = []
  let rowHeight = 0
  let rendered: { start: number; end: number } | null = null
  let frame = 0

  const spacer = (height: number): HTMLTableRowElement => {
    const tr = document.createElement('tr')
    tr.className = 'row-spacer'
    tr.setAttribute('aria-hidden', 'true')
    const td = document.createElement('td')
    td.colSpan = columns
    td.style.height = `${height}px`
    td.style.padding = '0'
    td.style.border = 'none'
    tr.appendChild(td)
    return tr
  }

  const paint = (start: number, end: number, pad: boolean): void => {
    const fragment = document.createDocumentFragment()
    if (pad && start > 0) fragment.appendChild(spacer(start * rowHeight))
    for (let i = start; i < end; i++) {
      const item = rows[i]
      if (item !== undefined) fragment.appendChild(renderRow(item))
    }
    if (pad && end < rows.length) fragment.appendChild(spacer((rows.length - end) * rowHeight))
    body.replaceChildren(fragment)
    rendered = { start, end }
  }

  const measureRowHeight = (): number => {
    const probe = body.querySelector<HTMLElement>('tr:not(.row-spacer)')
    return probe?.offsetHeight ?? 0
  }

  const render = (force: boolean): void => {
    if (rows.length === 0) {
      body.innerHTML = renderEmpty()
      rendered = null
      return
    }
    if (!scroller || rows.length <= threshold) {
      paint(0, rows.length, false)
      return
    }
    if (rowHeight <= 0) {
      // First pass without spacers so a real row can be measured.
      paint(0, Math.min(threshold, rows.length), false)
      rowHeight = measureRowHeight()
      if (rowHeight <= 0) return
    }
    const visible = Math.ceil(scroller.clientHeight / rowHeight)
    const start = Math.max(0, Math.floor(scroller.scrollTop / rowHeight) - overscan)
    const end = Math.min(rows.length, start + visible + overscan * 2)
    if (!force && rendered && rendered.start === start && rendered.end === end) return
    paint(start, end, true)
  }

  const scheduleRender = (): void => {
    if (frame) return
    frame = requestAnimationFrame(() => {
      frame = 0
      render(false)
    })
  }

  if (scroller) {
    scroller.addEventListener('scroll', scheduleRender, { passive: true })
    if (typeof ResizeObserver === 'function') {
      new ResizeObserver(() => {
        // Row height can change with the column width, so re-measure.
        rowHeight = 0
        render(true)
      }).observe(scroller)
    }
  }

  return {
    setRows(next) {
      rows = next
      render(true)
    }
  }
}
