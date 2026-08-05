import { inflateRawSync } from 'zlib'
import { describe, expect, it } from 'vitest'
import { exportReportZip } from '../src/main/export'
import { reportToAggregateXml, reportZipBasename } from '../src/main/report-xml'
import { crc32, zipSingleFile } from '../src/main/zip'
import type { ReportRow } from '../src/shared/types'

const sampleReport: ReportRow = {
  reportId: 'abc/123',
  orgName: 'google.com',
  domain: 'example.com',
  dateBegin: '2026-08-04T00:00:00.000Z',
  dateEnd: '2026-08-05T00:00:00.000Z',
  total: 3,
  passing: 3,
  failing: 0,
  passRate: 100,
  policyP: 'reject',
  records: [
    {
      sourceIp: '203.0.113.10',
      count: 3,
      disposition: 'none',
      dkimResult: 'pass',
      spfResult: 'pass',
      headerFrom: 'example.com',
      dkimDomain: 'example.com',
      spfDomain: 'example.com',
      dkimSelectors: ['mail'],
      passesDmarc: true,
      reasons: []
    }
  ]
}

describe('report XML / ZIP export', () => {
  it('builds aggregate XML with core fields', () => {
    const begin = Math.floor(Date.parse(sampleReport.dateBegin) / 1000)
    const end = Math.floor(Date.parse(sampleReport.dateEnd) / 1000)
    const xml = reportToAggregateXml(sampleReport)
    expect(xml).toContain('<org_name>google.com</org_name>')
    expect(xml).toContain('<report_id>abc/123</report_id>')
    expect(xml).toContain('<domain>example.com</domain>')
    expect(xml).toContain('<source_ip>203.0.113.10</source_ip>')
    expect(xml).toContain('<selector>mail</selector>')
    expect(xml).toContain(`<begin>${begin}</begin>`)
    expect(xml).toContain(`<end>${end}</end>`)
  })

  it('sanitizes zip basename', () => {
    const begin = Math.floor(Date.parse(sampleReport.dateBegin) / 1000)
    const end = Math.floor(Date.parse(sampleReport.dateEnd) / 1000)
    expect(reportZipBasename(sampleReport)).toBe(`example.com!abc_123!${begin}!${end}`)
  })

  it('packs a readable single-file zip', () => {
    const payload = Buffer.from('hello zip', 'utf8')
    const zip = zipSingleFile('hello.txt', payload)
    expect(zip.readUInt32LE(0)).toBe(0x04034b50)

    // Local header: 30 + nameLen, then compressed payload.
    const nameLen = zip.readUInt16LE(26)
    const compSize = zip.readUInt32LE(18)
    const dataStart = 30 + nameLen
    const inflated = inflateRawSync(zip.subarray(dataStart, dataStart + compSize))
    expect(inflated.toString('utf8')).toBe('hello zip')
    expect(crc32(payload)).toBe(zip.readUInt32LE(14))
  })

  it('exportReportZip returns zip bytes and filename', () => {
    const { filename, data } = exportReportZip(sampleReport)
    expect(filename.endsWith('.zip')).toBe(true)
    expect(data.readUInt32LE(0)).toBe(0x04034b50)
    expect(data.length).toBeGreaterThan(40)
  })
})
