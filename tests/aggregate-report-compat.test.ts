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

  it('ignores foreign forwarder DKIM selectors when serializing reports', async () => {
    const { parseLocalBuffers } = await import('../src/main/analyze')
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>rep-forwarder</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>kinderarztpraxis-teichler.de</domain>
    <p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>87.238.197.45</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>kinderarztpraxis-teichler.de</header_from></identifiers>
    <auth_results>
      <dkim>
        <domain>server109.greatnet.de</domain>
        <selector>rsa1</selector>
        <result>pass</result>
      </dkim>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>212.227.15.3</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>kinderarztpraxis-teichler.de</header_from></identifiers>
    <auth_results>
      <dkim>
        <domain>uni-halle.de</domain>
        <selector>uhal1dkim</selector>
        <result>pass</result>
      </dkim>
      <dkim>
        <domain>kinderarztpraxis-teichler.de</domain>
        <selector>agenturserver2048</selector>
        <result>pass</result>
      </dkim>
    </auth_results>
  </record>
</feedback>`
    const res = await parseLocalBuffers([{ name: 'report.xml', data: Buffer.from(xml, 'utf8') }])
    expect(res.reports[0]?.records[0]?.dkimDomain).toBe('server109.greatnet.de')
    expect(res.reports[0]?.records[0]?.dkimSelectors).toEqual([])
    expect(res.reports[0]?.records[1]?.dkimDomain).toBe('kinderarztpraxis-teichler.de')
    expect(res.reports[0]?.records[1]?.dkimSelectors).toEqual(['agenturserver2048'])
  })
})
