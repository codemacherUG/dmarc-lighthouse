import { describe, expect, it } from 'vitest'
import { ipSortKey } from '../src/shared/ipcidr'
import {
  compareIp,
  compareNumber,
  compareText,
  sortRows,
  type SortState
} from '../src/renderer/src/table'

describe('ipSortKey', () => {
  it('orders IPv4 numerically, not lexicographically', () => {
    const a = ipSortKey('10.0.0.9')!
    const b = ipSortKey('10.0.0.10')!
    expect(a < b).toBe(true)
  })

  it('sorts IPv4 before IPv6', () => {
    expect(ipSortKey('255.255.255.255')! < ipSortKey('::1')!).toBe(true)
  })

  it('expands compressed IPv6', () => {
    expect(ipSortKey('2001:db8::1')).toBe(ipSortKey('2001:0db8:0000:0000:0000:0000:0000:0001'))
  })

  it('returns null for non-IP values', () => {
    expect(ipSortKey('(unbekannt)')).toBeNull()
    expect(ipSortKey('')).toBeNull()
  })
})

describe('compareIp', () => {
  it('sorts a mixed list in numeric order', () => {
    const ips = ['192.168.0.100', '10.0.0.2', '192.168.0.9', '2001:db8::1', '10.0.0.10']
    expect([...ips].sort(compareIp)).toEqual([
      '10.0.0.2',
      '10.0.0.10',
      '192.168.0.9',
      '192.168.0.100',
      '2001:db8::1'
    ])
  })

  it('falls back to text order for non-IP values', () => {
    expect(compareIp('(unbekannt)', '10.0.0.1')).toBeLessThan(0)
  })
})

describe('compareText', () => {
  it('ignores case and orders numbers naturally', () => {
    expect(compareText('Alpha', 'alpha')).toBe(0)
    expect(compareText('report 2', 'report 10')).toBeLessThan(0)
  })

  it('treats null as an empty string', () => {
    expect(compareText(null, 'a')).toBeLessThan(0)
  })
})

describe('sortRows', () => {
  type Row = { name: string; count: number }
  const rows: Row[] = [
    { name: 'b', count: 2 },
    { name: 'a', count: 3 },
    { name: 'c', count: 1 }
  ]
  const compare = (a: Row, b: Row, key: 'name' | 'count'): number =>
    key === 'count' ? compareNumber(a.count, b.count) : compareText(a.name, b.name)

  it('sorts ascending and descending without mutating the input', () => {
    const asc: SortState<'name' | 'count'> = { key: 'count', dir: 'asc' }
    expect(sortRows(rows, asc, compare).map((r) => r.count)).toEqual([1, 2, 3])

    const desc: SortState<'name' | 'count'> = { key: 'name', dir: 'desc' }
    expect(sortRows(rows, desc, compare).map((r) => r.name)).toEqual(['c', 'b', 'a'])

    expect(rows.map((r) => r.name)).toEqual(['b', 'a', 'c'])
  })
})
