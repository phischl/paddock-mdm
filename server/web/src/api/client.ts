import createClient, { type Middleware } from 'openapi-fetch'
import type { components, paths } from './schema'

export type Me = components['schemas']['Me']
export type DeviceGroup = components['schemas']['DeviceGroup']
export type Organization = components['schemas']['Organization']
export type AuditEvent = components['schemas']['AuditEvent']
export type Problem = components['schemas']['Problem']

/** Sends the CSRF header on mutating requests and sends the browser to the login on 401. */
const middleware: Middleware = {
  onRequest({ request }) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      request.headers.set('X-Paddock-CSRF', '1')
    }
    return request
  },
  onResponse({ response }) {
    if (response.status === 401) {
      redirectToLogin()
    }
    return response
  },
}

export function redirectToLogin(): void {
  const returnTo = window.location.pathname + window.location.search
  window.location.assign('/api/auth/login?return_to=' + encodeURIComponent(returnTo))
}

export const api = createClient<paths>({ baseUrl: window.location.origin, credentials: 'same-origin' })
api.use(middleware)

/** Problem code of an error body, or "internal". */
export function problemCode(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error && typeof error.code === 'string') {
    return error.code
  }
  return 'internal'
}
