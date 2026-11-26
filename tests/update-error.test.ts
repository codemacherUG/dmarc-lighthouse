import { describe, expect, it } from 'vitest'
import { describeUpdateError } from '../src/main/update-error'

const FEED_ERROR =
  'Cannot parse releases feed: Error: Unable to find latest version on GitHub ' +
  '(https://github.com/codemacherUG/dmarc-lighthouse/releases/latest), please ensure a production release exists: ' +
  'Error: net::ERR_NETWORK_CHANGED\n' +
  '    at SimpleURLLoaderWrapper.<anonymous> (node:electron/js2c/browser_init:2:139483)\n' +
  '    at SimpleURLLoaderWrapper.emit (node:events:514:28)\n' +
  '    at newError (/tmp/.mount_dmarc-q4mblp/resources/app.asar/node_modules/builder-util-runtime/out/error.js:5:19), ' +
  'XML: <?xml version="1.0" encoding="UTF-8"?> <feed xmlns="http://www.w3.org/2005/Atom"> ' +
  '<title>Release notes from dmarc-lighthouse</title> </feed>'

describe('describeUpdateError', () => {
  it('recognises a network change during the releases-feed lookup as transient', () => {
    const info = describeUpdateError(new Error(FEED_ERROR))
    expect(info.transient).toBe(true)
    expect(info.code).toBe('ERR_NETWORK_CHANGED')
  })

  it('strips the stack trace and the feed XML from the detail', () => {
    const { detail } = describeUpdateError(new Error(FEED_ERROR))
    expect(detail).not.toContain('XML')
    expect(detail).not.toContain('<feed')
    expect(detail).not.toContain('SimpleURLLoaderWrapper')
    expect(detail).not.toContain('\n')
    expect(detail.length).toBeLessThanOrEqual(200)
  })

  it('handles the same error when whitespace was collapsed to single spaces', () => {
    const info = describeUpdateError(FEED_ERROR.replace(/\s+/g, ' '))
    expect(info.transient).toBe(true)
    expect(info.detail).not.toContain('SimpleURLLoaderWrapper')
  })

  it('treats Node DNS/socket errors as transient', () => {
    const info = describeUpdateError(new Error('getaddrinfo ENOTFOUND github.com'))
    expect(info).toMatchObject({ transient: true, code: 'ENOTFOUND' })
  })

  it('does not treat certificate or HTTP errors as transient', () => {
    expect(describeUpdateError(new Error('net::ERR_CERT_AUTHORITY_INVALID')).transient).toBe(false)
    const http = describeUpdateError(new Error('HttpError: 404 Not Found'))
    expect(http).toMatchObject({ transient: false, code: null, detail: 'HttpError: 404 Not Found' })
  })

  it('ignores error codes that only appear inside the feed body', () => {
    const info = describeUpdateError(
      'Cannot parse releases feed: boom, XML: <feed>fix net::ERR_TIMED_OUT</feed>'
    )
    expect(info).toMatchObject({
      transient: false,
      code: null,
      detail: 'Cannot parse releases feed: boom'
    })
  })

  it('never returns an empty detail', () => {
    expect(describeUpdateError(undefined).detail).toBe('Unknown error')
  })
})
