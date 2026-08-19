import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { parseDmarcXml, recordPassesDmarc, summarize } from '@koduhai/dmarc-parser'

/**
 * Regression coverage for RFC 9990: the aggregate report XML schema gained a new
 * namespace, a `2.0` version, `np`/`t`/`psd` policy_published tags and an <extensions>
 * block. Lighthouse must keep ingesting both the legacy (RFC 7489) and the new schema.
 */
function loadFixture(name: string): string {
  return readFileSync(join(__dirname, 'fixtures', name), 'utf8')
}

describe('aggregate report schema compatibility', () => {
  it('parses a legacy RFC 7489-style report (pct, no np/t/psd)', () => {
    const xml = loadFixture('aggregate-report-v1.xml')
    const report = parseDmarcXml(xml)

    expect(report.meta.orgName).toBe('legacy-sender.example')
    expect(report.meta.domain).toBe('example.com')
    expect(report.meta.policyP).toBe('quarantine')
    expect(report.meta.policyPct).toBe(25)
    expect(report.records).toHaveLength(1)

    const summary = summarize(report)
    expect(summary.total).toBe(12)
    expect(summary.passing).toBe(12)
    expect(recordPassesDmarc(report.records[0])).toBe(true)
  })

  it('parses a DMARC 2.0 / RFC 9990-style report (new namespace, np/t/psd, extensions)', () => {
    const xml = loadFixture('aggregate-report-dmarc2.xml')
    const report = parseDmarcXml(xml)

    expect(report.meta.orgName).toBe('dmarc2-sender.example')
    expect(report.meta.domain).toBe('example.com')
    expect(report.meta.policyP).toBe('reject')
    // np= (RFC 9989/9990) is already surfaced by the parser today.
    expect(report.meta.policyNp).toBe('reject')
    expect(report.records).toHaveLength(1)

    const summary = summarize(report)
    expect(summary.total).toBe(7)
    // dkim fail + spf pass -> still an aligned pass via SPF.
    expect(recordPassesDmarc(report.records[0])).toBe(true)
    expect(summary.passing).toBe(7)
  })

  it('does not throw when unknown 2.0 extension elements are present', () => {
    const xml = loadFixture('aggregate-report-dmarc2.xml')
    expect(() => parseDmarcXml(xml)).not.toThrow()
  })
})
