import { beforeEach, describe, expect, it, vi } from 'vitest'

const appFetch = vi.fn()
const openExternalSafe = vi.fn()

vi.mock('../src/main/http', () => ({
  appFetch: (...args: unknown[]) => appFetch(...args)
}))

vi.mock('../src/main/open-external', () => ({
  openExternalSafe: (...args: unknown[]) => openExternalSafe(...args)
}))

function jsonResponse(
  body: Record<string, unknown>,
  ok = true,
  status = 200
): {
  ok: boolean
  status: number
  statusText: string
  json: () => Promise<Record<string, unknown>>
} {
  return {
    ok,
    status,
    statusText: ok ? 'OK' : 'Bad Request',
    json: async () => body
  }
}

describe('oauth', () => {
  beforeEach(() => {
    appFetch.mockReset()
    openExternalSafe.mockReset()
  })

  it('includes client_secret in Google authorization_code exchange when configured', async () => {
    const { authorizeInteractive } = await import('../src/main/oauth')

    openExternalSafe.mockImplementation(async (authUrl: string) => {
      const parsed = new URL(authUrl)
      const redirectUri = parsed.searchParams.get('redirect_uri')!
      const state = parsed.searchParams.get('state')!
      const callbackUrl = new URL(redirectUri)
      callbackUrl.searchParams.set('state', state)
      callbackUrl.searchParams.set('code', 'auth-code-123')
      await fetch(callbackUrl.toString())
    })

    appFetch.mockImplementation(async (url: string) => {
      if (url === 'https://oauth2.googleapis.com/token') {
        return jsonResponse({
          access_token: 'ya29.access',
          refresh_token: '1//refresh',
          expires_in: 3600
        })
      }
      if (url === 'https://openidconnect.googleapis.com/v1/userinfo') {
        return jsonResponse({ email: 'user@example.com' })
      }
      throw new Error(`Unexpected URL: ${url}`)
    })

    const tokens = await authorizeInteractive('google', {
      googleClientId: 'google-client-id.apps.googleusercontent.com',
      googleClientSecret: 'GOCSPX-secret-value',
      microsoftClientId: ''
    })

    expect(tokens.accessToken).toBe('ya29.access')
    expect(tokens.refreshToken).toBe('1//refresh')
    expect(tokens.email).toBe('user@example.com')

    const tokenCall = appFetch.mock.calls.find(
      (c) => c[0] === 'https://oauth2.googleapis.com/token'
    )
    expect(tokenCall).toBeDefined()
    const bodyParams = new URLSearchParams((tokenCall![1] as { body: string }).body)
    expect(bodyParams.get('client_id')).toBe('google-client-id.apps.googleusercontent.com')
    expect(bodyParams.get('client_secret')).toBe('GOCSPX-secret-value')
    expect(bodyParams.get('grant_type')).toBe('authorization_code')
    expect(bodyParams.get('code')).toBe('auth-code-123')
    expect(bodyParams.get('code_verifier')).toBeTruthy()
  })

  it('includes client_secret in Google refresh_token request when configured', async () => {
    const { refreshAccessToken } = await import('../src/main/oauth')

    appFetch.mockResolvedValue(
      jsonResponse({
        access_token: 'ya29.refreshed',
        expires_in: 3600
      })
    )

    const tokens = await refreshAccessToken(
      'google',
      {
        googleClientId: 'google-client-id.apps.googleusercontent.com',
        googleClientSecret: 'GOCSPX-secret-value',
        microsoftClientId: ''
      },
      '1//stored-refresh',
      'user@example.com'
    )

    expect(tokens.accessToken).toBe('ya29.refreshed')
    expect(tokens.refreshToken).toBe('1//stored-refresh')
    const bodyParams = new URLSearchParams((appFetch.mock.calls[0]![1] as { body: string }).body)
    expect(bodyParams.get('client_id')).toBe('google-client-id.apps.googleusercontent.com')
    expect(bodyParams.get('client_secret')).toBe('GOCSPX-secret-value')
    expect(bodyParams.get('grant_type')).toBe('refresh_token')
    expect(bodyParams.get('refresh_token')).toBe('1//stored-refresh')
  })

  it('maps Google "client_secret is missing." error to localized message', async () => {
    const { refreshAccessToken } = await import('../src/main/oauth')

    appFetch.mockResolvedValue(
      jsonResponse(
        {
          error: 'invalid_request',
          error_description: 'client_secret is missing.'
        },
        false,
        400
      )
    )

    await expect(
      refreshAccessToken(
        'google',
        {
          googleClientId: 'google-client-id.apps.googleusercontent.com',
          microsoftClientId: ''
        },
        '1//stored-refresh',
        'user@example.com'
      )
    ).rejects.toThrow(/DMARC_GOOGLE_CLIENT_SECRET/)
  })
})
