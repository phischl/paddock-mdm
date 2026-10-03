import createClient, { type Middleware } from 'openapi-fetch'
import type { components, paths } from './schema'
import { ListError, type Page } from '../lib/listQuery'

export type Me = components['schemas']['Me']
export type DeviceGroup = components['schemas']['DeviceGroup']
export type Organization = components['schemas']['Organization']
export type AuditEvent = components['schemas']['AuditEvent']
export type Problem = components['schemas']['Problem']
export type DeviceGroupSort = components['parameters']['DeviceGroupSort']
export type AuditEventSort = components['parameters']['AuditEventSort']
export type OrganizationSort = components['parameters']['OrganizationSort']
export type AuditOutcome = components['schemas']['AuditOutcome']
export type AuditActorType = components['schemas']['AuditActorType']
export type OrganizationStatus = components['schemas']['OrganizationStatus']

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

/** The page of a list response; a problem becomes a ListError for DataList. */
export function listPage<T>(res: { data?: Page<T>; error?: unknown }): Page<T> {
  if (res.error || !res.data) throw new ListError(problemCode(res.error))
  return res.data
}
