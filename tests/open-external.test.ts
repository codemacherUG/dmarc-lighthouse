import { beforeEach, describe, expect, it, vi } from 'vitest'

const openExternal = vi.fn(async () => undefined)

vi.mock('electron', () => ({
  shell: { openExternal }
}))

describe('openExternalSafe', () => {
  beforeEach(() => {
    openExternal.mockClear()
  })

  it('allows https and mailto', async () => {
    const { openExternalSafe } = await import('../src/main/open-external')
    await openExternalSafe('https://example.com/path')
    await openExternalSafe('mailto:user@example.com')
    expect(openExternal).toHaveBeenCalledTimes(2)
  })

  it('blocks dangerous schemes', async () => {
    const { openExternalSafe } = await import('../src/main/open-external')
    await expect(openExternalSafe('file:///etc/passwd')).rejects.toThrow(/Blocked URL scheme/)
    await expect(openExternalSafe('javascript:alert(1)')).rejects.toThrow(/Blocked URL scheme/)
    await expect(openExternalSafe('http://example.com')).rejects.toThrow(/Blocked URL scheme/)
    expect(openExternal).not.toHaveBeenCalled()
  })
})
