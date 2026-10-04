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
export type Device = components['schemas']['Device']
export type DeviceDetail = components['schemas']['DeviceDetail']
export type DeviceReport = components['schemas']['DeviceReport']
export type DeviceState = components['schemas']['DeviceState']
export type DeviceSort = components['parameters']['DeviceSort']
export type EffectiveConfig = components['schemas']['EffectiveConfig']
export type EnrollmentToken = components['schemas']['EnrollmentToken']
export type EnrollmentTokenCreated = components['schemas']['EnrollmentTokenCreated']
export type EnrollmentTokenSort = components['parameters']['EnrollmentTokenSort']
export type ManagedFile = components['schemas']['ManagedFile']
export type ManagedFileSort = components['parameters']['ManagedFileSort']
export type ManagedUnit = components['schemas']['ManagedUnit']
export type ManagedUnitSort = components['parameters']['ManagedUnitSort']
export type AgentRelease = components['schemas']['AgentRelease']
export type AgentReleaseDetail = components['schemas']['AgentReleaseDetail']
export type AgentReleaseSort = components['parameters']['AgentReleaseSort']
export type AgentReleaseStatus = components['schemas']['AgentReleaseStatus']
export type AgentRolloutStatus = components['schemas']['AgentRolloutStatus']
export type User = components['schemas']['User']
export type UserDetail = components['schemas']['UserDetail']
export type UserCreated = components['schemas']['UserCreated']
export type UserSort = components['parameters']['UserSort']
export type IdentitySource = components['schemas']['IdentitySource']
export type UserGroup = components['schemas']['UserGroup']
export type UserGroupSort = components['parameters']['UserGroupSort']
export type UpstreamGroup = components['schemas']['UpstreamGroup']
export type UpstreamGroupSort = components['parameters']['UpstreamGroupSort']
export type LoginSettings = components['schemas']['LoginSettings']
export type LoginSettingsUpdate = components['schemas']['LoginSettingsUpdate']
export type SessionAction = components['schemas']['SessionAction']
export type PermissionProfile = components['schemas']['PermissionProfile']
export type PermissionProfileSort = components['parameters']['PermissionProfileSort']
export type PrivilegeClass = components['schemas']['PrivilegeClass']
export type Lecture = components['schemas']['Lecture']
export type SubjectType = components['schemas']['SubjectType']
export type ProfileAssignment = components['schemas']['ProfileAssignment']
export type ProfileAssignmentSort = components['parameters']['ProfileAssignmentSort']
export type UserEffectiveProfile = components['schemas']['UserEffectiveProfile']
export type EffectiveSudo = components['schemas']['EffectiveSudo']

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
