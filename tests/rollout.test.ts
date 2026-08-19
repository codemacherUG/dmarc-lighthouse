import { describe, expect, it } from 'vitest'
import { assessRollout, readCurrentPolicy, reportsForRollout } from '../src/shared/rollout'
import type { DnsCheckResult, ReportRow, SerializedRecord } from '../src/shared/types'

const NOW = new Date('2026-08-01T00:00:00.000Z')

function rec(overrides: Partial<SerializedRecord> = {}): SerializedRecord {
  return {
    sourceIp: '192.0.2.1',
    count: 1,
    disposition: 'none',
    dkimResult: 'pass',
    spfResult: 'pass',
    headerFrom: 'example.com',
    dkimDomain: 'example.com',
    spfDomain: 'example.com',
    dkimSelectors: ['sel1'],
    passesDmarc: true,
    reasons: [],
    ...overrides
  }
}

function report(overrides: Partial<ReportRow> = {}): ReportRow {
  const records = overrides.records ?? [rec()]
  let total = 0
  let passing = 0
  for (const r of records) {
    total += r.count
    if (r.passesDmarc) passing += r.count
  }
  return {
    reportId: 'r-1',
    orgName: 'google.com',
    domain: 'example.com',
    dateBegin: '2026-07-01T00:00:00.000Z',
    dateEnd: '2026-07-02T00:00:00.000Z',
    total,
    passing,
    failing: total - passing,
    passRate: total ? Math.round((passing / total) * 1000) / 10 : 0,
    policyP: 'none',
    ...overrides,
    records
  }
}

function dns(
  overrides: { record?: string | null; spf?: boolean; dkim?: boolean } = {}
): DnsCheckResult {
  const record =
    overrides.record === undefined
      ? 'v=DMARC1; p=none; rua=mailto:dmarc@example.com'
      : overrides.record
  return {
    domain: 'example.com',
    dmarc: {
      found: Boolean(record),
      records: record ? [record] : [],
      policy: record ? (/p=(\w+)/.exec(record)?.[1] ?? null) : null,
      rua: null,
      ruf: null
    },
    spf: { found: overrides.spf ?? true, records: ['v=spf1 -all'] },
    dkim: { selectors: [{ selector: 'sel1', found: overrides.dkim ?? true, record: null }] },
    checkedAt: NOW.toISOString()
  }
}

/** Healthy traffic plus a controlled share of delivered legit-looking fails. */
function traffic(input: {
  pass: number
  risk?: number
  spoof?: number
  days?: number
}): ReportRow[] {
  const days = input.days ?? 20
  const start = new Date(NOW.getTime() - days * 86_400_000)
  const records = [rec({ count: input.pass })]
  if (input.risk) {
    records.push(
      rec({
        sourceIp: '203.0.113.7',
        count: input.risk,
        passesDmarc: false,
        dkimResult: 'fail',
        spfResult: 'fail',
        dkimDomain: 'sendgrid.net',
        spfDomain: 'sendgrid.net'
      })
    )
  }
  if (input.spoof) {
    records.push(
      rec({
        sourceIp: '198.51.100.9',
        count: input.spoof,
        passesDmarc: false,
        dkimResult: 'fail',
        spfResult: 'fail',
        dkimDomain: null,
        spfDomain: null
      })
    )
  }
  return [
    report({
      reportId: 'r-window',
      dateBegin: start.toISOString(),
      dateEnd: new Date(NOW.getTime() - 86_400_000).toISOString(),
      records
    })
  ]
}

describe('readCurrentPolicy', () => {
  it('reads policy, legacy pct and rua from the published record', () => {
    const current = readCurrentPolicy(
      dns({ record: 'v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com' })
    )
    expect(current).toMatchObject({
      found: true,
      policy: 'quarantine',
      pct: 25,
      testing: true,
      rua: 'd@example.com'
    })
  })

  it('reads t=y as testing on a full-pct record', () => {
    const current = readCurrentPolicy(
      dns({ record: 'v=DMARC1; p=quarantine; t=y; rua=mailto:d@example.com' })
    )
    expect(current).toMatchObject({ policy: 'quarantine', pct: 100, testing: true })
  })

  it('reports a missing record and unknown DNS', () => {
    expect(readCurrentPolicy(dns({ record: null }))).toMatchObject({ found: false, policy: null })
    expect(readCurrentPolicy(null)).toMatchObject({ found: false, spfOk: null, dkimOk: null })
  })
})

describe('reportsForRollout', () => {
  it('keeps only the domain inside the window', () => {
    const rows = [
      report({ reportId: 'in', dateEnd: '2026-07-28T00:00:00.000Z' }),
      report({ reportId: 'old', dateEnd: '2026-06-01T00:00:00.000Z' }),
      report({ reportId: 'other', domain: 'other.example', dateEnd: '2026-07-28T00:00:00.000Z' })
    ]
    const out = reportsForRollout(rows, 'EXAMPLE.com', { now: NOW, windowDays: 30 })
    expect(out.map((r) => r.reportId)).toEqual(['in'])
  })
})

describe('assessRollout', () => {
  it('recommends publishing p=none when no record exists', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: [],
      dns: dns({ record: null }),
      now: NOW
    })
    expect(out.currentStage).toBeNull()
    expect(out.nextStage).toBe('monitor')
    expect(out.ready).toBe(true)
    expect(out.plan[0]).toMatchObject({
      state: 'next',
      record: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com; adkim=r; aspf=r'
    })
  })

  it('waits for DNS before recommending anything', () => {
    const out = assessRollout({ domain: 'example.com', reports: [], dns: null, now: NOW })
    expect(out.ready).toBe(false)
    expect(out.blockers.map((b) => b.key)).toEqual(['dnsPending'])
  })

  it('advances from monitoring once the risky share is small enough', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 990, risk: 10 }),
      dns: dns(),
      now: NOW
    })
    expect(out.currentStage).toBe('monitor')
    expect(out.nextStage).toBe('quarantinePartial')
    expect(out.metrics.riskRate).toBe(1)
    expect(out.ready).toBe(true)
    expect(out.plan.map((s) => s.state)).toEqual(['current', 'next', 'later', 'later', 'later'])
  })

  it('blocks the step while too many legitimate senders still fail', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 900, risk: 100 }),
      dns: dns({ record: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com' }),
      now: NOW
    })
    expect(out.currentStage).toBe('quarantineFull')
    expect(out.nextStage).toBe('rejectPartial')
    expect(out.ready).toBe(false)
    expect(out.blockers).toEqual([{ key: 'highRisk', actual: 10, limit: 1 }])
  })

  it('does not count spoofing as a risk for the next step', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 800, spoof: 200 }),
      dns: dns(),
      now: NOW
    })
    expect(out.metrics.spoof).toBe(200)
    expect(out.metrics.risk).toBe(0)
    expect(out.ready).toBe(true)
  })

  it('requires enough volume and observation time', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 20, days: 3 }),
      dns: dns(),
      now: NOW
    })
    expect(out.blockers.map((b) => b.key)).toEqual(['lowVolume', 'shortWindow'])
    expect(out.ready).toBe(false)
  })

  it('flags a broken SPF or DKIM setup as a blocker', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 1000 }),
      dns: dns({ spf: false, dkim: false }),
      now: NOW
    })
    expect(out.blockers.map((b) => b.key)).toEqual(['noSpf', 'dkimMissing'])
  })

  it('keeps the published reporting and alignment tags in every planned step', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 1000 }),
      dns: dns({ record: 'v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@x.test; adkim=s' }),
      now: NOW
    })
    const rejectFull = out.plan.at(-1)
    expect(rejectFull).toMatchObject({
      id: 'rejectFull',
      host: '_dmarc.example.com',
      record: 'v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@x.test; adkim=s; aspf=r'
    })
    expect(out.plan[3]?.record).toContain('t=y')
  })

  it('has nothing left to recommend at p=reject with full coverage', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 1000 }),
      dns: dns({ record: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com' }),
      now: NOW
    })
    expect(out.currentStage).toBe('rejectFull')
    expect(out.nextStage).toBeNull()
    expect(out.ready).toBe(false)
    expect(out.plan.map((s) => s.state)).toEqual(['done', 'done', 'done', 'done', 'current'])
  })

  it('lists the riskiest senders with their dominant category', () => {
    const out = assessRollout({
      domain: 'example.com',
      reports: traffic({ pass: 900, risk: 40, spoof: 60 }),
      dns: dns(),
      now: NOW
    })
    expect(out.riskSources).toEqual([
      { sourceIp: '203.0.113.7', count: 40, category: 'thirdParty', headerFrom: 'example.com' }
    ])
  })
})
