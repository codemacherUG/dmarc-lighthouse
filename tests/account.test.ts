import { describe, expect, it } from 'vitest'
import {
  ALL_ACCOUNTS_ID,
  isAllAccountsId,
  resolveAccountLabel,
  suggestAccountName
} from '../src/shared/account'

describe('isAllAccountsId', () => {
  it('recognizes the all-accounts sentinel', () => {
    expect(isAllAccountsId(ALL_ACCOUNTS_ID)).toBe(true)
    expect(isAllAccountsId('__all__')).toBe(true)
    expect(isAllAccountsId('acc-1')).toBe(false)
    expect(isAllAccountsId(null)).toBe(false)
    expect(isAllAccountsId(undefined)).toBe(false)
  })
})

describe('suggestAccountName', () => {
  it('uses the email domain', () => {
    expect(suggestAccountName('dmarc@codemacher.de', 'mail.codemacher.de')).toBe('codemacher.de')
  })

  it('falls back to a cleaned host without mail./imap. prefix', () => {
    expect(suggestAccountName('reports', 'imap.example.org')).toBe('example.org')
    expect(suggestAccountName('', 'mail.firma.de')).toBe('firma.de')
  })

  it('falls back to IMAP when nothing useful is set', () => {
    expect(suggestAccountName('', '')).toBe('IMAP')
  })
})

describe('resolveAccountLabel', () => {
  it('prefers a custom name', () => {
    expect(
      resolveAccountLabel({
        name: 'Kundenmail',
        user: 'dmarc@codemacher.de',
        host: 'mail.codemacher.de'
      })
    ).toBe('Kundenmail')
  })

  it('uses the suggested domain when the custom name is empty', () => {
    expect(
      resolveAccountLabel({
        name: '  ',
        user: 'dmarc@codemacher.de',
        host: 'mail.codemacher.de'
      })
    ).toBe('codemacher.de')
  })
})
