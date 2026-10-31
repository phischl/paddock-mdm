import type { RouteLocationRaw } from 'vue-router'
import { api } from '../api/client'

/** The getting-started guide, for the steps that need the host shell (PDK-200, plan M9 amendment 2026-10-31 D5). */
export const gettingStartedGuide = 'https://github.com/phischl/paddock-mdm/blob/main/docs/operations/getting-started.md'

/**
 * done and open are read from the API; unknown means the read failed (never shown as done); manual steps need the
 * host shell or the identity provider and are shown as text with a link to the guide.
 */
export type StepState = 'done' | 'open' | 'unknown' | 'manual'

export interface SetupStep {
  key: string
  /** A message key below setup.steps. */
  label: string
  state: StepState
  /** The portal page that completes the step; absent for steps that need the host shell. */
  to?: RouteLocationRaw
}

/** What the signed-in role may open; the checklist lists only steps whose page it can reach. */
export interface SetupAccess {
  isPlatform: boolean
  canWrite: boolean
}

async function exists(read: () => Promise<{ total: number } | undefined>): Promise<StepState> {
  try {
    const page = await read()
    if (!page) return 'unknown'
    return page.total > 0 ? 'done' : 'open'
  } catch {
    return 'unknown'
  }
}

/** The localStorage key of the dismissal of one account. */
export function dismissKey(accountId: string): string {
  return `paddock.setup.dismissed.${accountId}`
}

/** Platform steps from the existing platform endpoints. */
async function platformSteps(): Promise<SetupStep[]> {
  const [organization, release, allowlist] = await Promise.all([
    exists(async () => (await api.GET('/api/platform/v1/organizations', { params: { query: { page_size: 10 } } })).data),
    exists(async () => (await api.GET('/api/platform/v1/agent-releases', { params: { query: { page_size: 10, status: ['published'] } } })).data),
    exists(async () => (await api.GET('/api/platform/v1/ip-allowlist', { params: { query: { page_size: 10 } } })).data),
  ])
  return [
    { key: 'organization', label: 'setup.steps.organization', state: organization, to: { name: 'organizations' } },
    { key: 'orgAdmin', label: 'setup.steps.orgAdmin', state: 'manual' },
    { key: 'release', label: 'setup.steps.release', state: release, to: { name: 'agent-releases' } },
    { key: 'allowlist', label: 'setup.steps.allowlist', state: allowlist, to: { name: 'ip-allowlist' } },
  ]
}

async function activeTokens(): Promise<{ total: number } | undefined> {
  const { data } = await api.GET('/api/v1/enrollment-tokens', { params: { query: { page_size: 100 } } })
  return data ? { total: data.items.filter((t) => t.status === 'active').length } : undefined
}

/** Organization steps from the existing organization endpoints; the token step needs write access. */
async function organizationSteps(access: SetupAccess): Promise<SetupStep[]> {
  const [breakGlass, users, tokens, devices] = await Promise.all([
    exists(async () => {
      const { data } = await api.GET('/api/v1/settings/login')
      return data ? { total: data.break_glass_accounts.length } : undefined
    }),
    exists(async () => (await api.GET('/api/v1/users', { params: { query: { page_size: 10, source: ['synced'] } } })).data),
    access.canWrite ? exists(activeTokens) : Promise.resolve<StepState>('open'),
    exists(async () => (await api.GET('/api/v1/devices', { params: { query: { page_size: 10, state: ['active'] } } })).data),
  ])
  const steps: SetupStep[] = [
    { key: 'breakGlass', label: 'setup.steps.breakGlass', state: breakGlass, to: { name: 'login-settings' } },
    { key: 'users', label: 'setup.steps.users', state: users, to: { name: 'users' } },
  ]
  if (access.canWrite) {
    steps.push({ key: 'token', label: 'setup.steps.token', state: tokens, to: { name: 'enrollment-tokens' } })
  }
  steps.push(
    { key: 'agent', label: 'setup.steps.agent', state: 'manual' },
    { key: 'device', label: 'setup.steps.device', state: devices, to: { name: 'devices' } },
  )
  return steps
}

/** The checklist of the signed-in role, every state computed from the list endpoints the portal already uses. */
export function loadSetupSteps(access: SetupAccess): Promise<SetupStep[]> {
  return access.isPlatform ? platformSteps() : organizationSteps(access)
}
