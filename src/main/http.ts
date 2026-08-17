import { app, net } from 'electron'
import { formatNetworkError } from './network-error'

export { formatNetworkError }

export type AppFetchInit = RequestInit & {
  bypassCustomProtocolHandlers?: boolean
}

/**
 * HTTPS via Chromium (`net.fetch`) when the app is ready — uses the OS trust
 * store and system proxy. Falls back to Node's fetch only before `app.ready`
 * (tests / early boot).
 */
export async function appFetch(input: string | URL, init?: AppFetchInit): Promise<Response> {
  const url = typeof input === 'string' ? input : input.toString()
  const { bypassCustomProtocolHandlers = true, ...requestInit } = init ?? {}

  if (app.isReady()) {
    try {
      return await net.fetch(url, {
        ...requestInit,
        bypassCustomProtocolHandlers
      })
    } catch (err) {
      throw wrapNetworkError(err)
    }
  }

  try {
    return await fetch(url, requestInit)
  } catch (err) {
    throw wrapNetworkError(err)
  }
}

function wrapNetworkError(err: unknown): Error {
  const message = formatNetworkError(err)
  if (err instanceof Error && err.message === message) return err
  const wrapped = new Error(message)
  wrapped.cause = err
  return wrapped
}
