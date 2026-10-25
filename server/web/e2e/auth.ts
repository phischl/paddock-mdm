import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { request, type APIResponse, type Page } from '@playwright/test'

const secrets = process.env.PADDOCK_E2E_SECRETS ?? '../../deploy/compose/.secrets'
const password = (file: string) => readFileSync(join(secrets, file), 'utf8').trim()
const baseURL = () => process.env.PADDOCK_E2E_BASE_URL ?? 'https://admin.paddock.localhost:8443'

/**
 * Signs in through Authentik's flow executor API — the same paddock-admin-login flow the Authentik login page
 * runs (development variant without MFA) — with the browser context's cookies, then opens the portal callback in
 * the browser. The Authentik UI itself is not under test.
 */
export async function login(page: Page, username: string, passwordFile: string): Promise<void> {
  await loginWithPassword(page, username, password(passwordFile))
}

/** login with the password itself, for a temporary user (tempUser). */
export async function loginWithPassword(page: Page, username: string, secret: string): Promise<void> {
  await follow(page, new URL('/api/auth/login?return_to=%2F', baseURL()).toString(), '/api/auth/callback', username, secret)
}

/** A temporary Authentik user of tempUser; remove deletes it. */
export interface TempUser {
  username: string
  password: string
  remove: () => Promise<void>
}

/**
 * Creates a temporary Authentik user in one group (e.g. paddock.acme.operators) through Authentik's admin API with
 * the bootstrap token, like the acceptance helper tempUser: the development stack seeds no user for every role.
 */
export async function tempUser(prefix: string, group: string): Promise<TempUser> {
  const api = await request.newContext({
    baseURL: (process.env.PADDOCK_E2E_AUTH_URL ?? 'https://auth.paddock.localhost:8443') + '/api/v3/',
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Authorization: 'Bearer ' + password('authentik_bootstrap_token'), Accept: 'application/json' },
  })
  const ok = async <T>(what: string, res: Promise<APIResponse>): Promise<T> => {
    const r = await res
    if (!r.ok()) throw new Error(`authentik ${what}: HTTP ${r.status()} ${await r.text()}`)
    return (r.status() === 204 ? undefined : await r.json()) as T
  }
  const username = `${prefix}-${randomBytes(6).toString('hex')}@e2e.test`
  const secret = 'pw-' + randomUUID()
  const groups = await ok<{ results: { pk: string; name: string }[] }>('group', api.get('core/groups/', { params: { name: group, include_users: 'false' } }))
  const groupPK = groups.results.find((g) => g.name === group)?.pk
  if (!groupPK) throw new Error(`authentik group ${group} not found`)
  const user = await ok<{ pk: number }>('create user', api.post('core/users/', {
    data: { username, name: username, email: username, is_active: true, type: 'internal' },
  }))
  const remove = async () => {
    await api.delete(`core/users/${user.pk}/`)
    await api.dispose()
  }
  try {
    await ok('set password', api.post(`core/users/${user.pk}/set_password/`, { data: { password: secret } }))
    await ok('add to group', api.post(`core/groups/${groupPK}/add_user/`, { data: { pk: user.pk } }))
  } catch (e) {
    await remove()
    throw e
  }
  return { username, password: secret, remove }
}

/**
 * Runs start, which makes the portal start a step-up (plan M4a decision 6), and completes it: the browser is kept
 * out of the paddock-stepup flow page (Authentik's UI would run the same flow), the flow is answered through the
 * executor API with the password and a TOTP code of the dev authenticator in totpKeyFile (devseed), then the
 * browser opens the step-up callback.
 */
export async function stepUp(page: Page, start: () => Promise<void>, username: string, passwordFile: string, totpKeyFile: string): Promise<void> {
  // The portal's own /api/auth/stepup request is held, not the flow page: Playwright does not route requests that a
  // redirect started, so the flow page loaded in the browser and Authentik's UI ran the flow alongside the executor
  // API below, which broke the step-up now and then (PDK-047). follow() walks the redirects with the context's cookies.
  // The URL is taken in the handler: the request event can arrive before it, and an unroute in between would let the
  // request through. The held navigation gets an empty page, not a 204: a 204 never commits the navigation, and since
  // Playwright 1.64 a click that started a navigation waits for it to commit, so start() would hang until the test
  // timeout.
  const stepUpStart = /\/api\/auth\/stepup\?/
  let held!: (url: string) => void
  const startUrl = new Promise<string>((resolve) => (held = resolve))
  await page.route(stepUpStart, async (route) => {
    held(route.request().url())
    await route.fulfill({ status: 200, contentType: 'text/html', body: '' })
  })
  await start()
  const url = await startUrl
  await page.unroute(stepUpStart)
  await follow(page, url, '/api/auth/stepup/callback', username, password(passwordFile), password(totpKeyFile))
}

async function follow(page: Page, start: string, callback: string, username: string, secret: string, totpKey?: string): Promise<void> {
  let next = start
  for (let hop = 0; hop < 30; hop++) {
    const url = new URL(next)
    if (url.hostname.startsWith('admin.') && url.pathname === callback) {
      await page.goto(next)
      return
    }
    if (url.pathname.startsWith('/if/flow/')) {
      next = await runFlow(page, url, username, secret, totpKey)
      continue
    }
    const res = await page.request.get(next, { maxRedirects: 0 })
    const location = res.headers()['location']
    if (!location) throw new Error(`login: ${next} answered ${res.status()} without a redirect`)
    next = new URL(location, next).toString()
  }
  throw new Error('login: too many redirects')
}

async function runFlow(page: Page, flowPage: URL, username: string, secret: string, totpKey?: string): Promise<string> {
  const slug = flowPage.pathname.replace(/^\/if\/flow\//, '').replace(/\/$/, '')
  const executor = new URL(`/api/v3/flows/executor/${slug}/`, flowPage)
  executor.searchParams.set('query', flowPage.search.replace(/^\?/, ''))
  let challenge = await (await page.request.get(executor.toString())).json()
  for (let step = 0; step < 10; step++) {
    let answer: Record<string, string>
    switch (challenge.component) {
      case 'xak-flow-redirect':
        return new URL(challenge.to, flowPage).toString()
      case 'ak-stage-identification':
        answer = { component: challenge.component, uid_field: username }
        break
      case 'ak-stage-password':
        answer = { component: challenge.component, password: secret }
        break
      case 'ak-stage-authenticator-validate':
        if (!totpKey) throw new Error(`login: flow ${slug} asks for MFA`)
        answer = { component: challenge.component, code: await totp(totpKey) }
        break
      default:
        throw new Error(`login: unexpected stage ${challenge.component} in flow ${slug}`)
    }
    // With a signed-in Authentik session (the step-up) Django checks the CSRF token and, over HTTPS, the Referer.
    const csrf = (await page.context().cookies(executor.origin)).find((c) => c.name === 'authentik_csrf')
    const res = await page.request.post(executor.toString(), {
      data: answer,
      headers: { Referer: flowPage.toString(), ...(csrf ? { 'X-authentik-CSRF': csrf.value } : {}) },
    })
    challenge = await res.json()
  }
  throw new Error(`login: flow ${slug} did not finish`)
}

// Authentik rejects a code whose 30 s step was already used, so a step-up shortly after another one with the same key
// (or a retry after a rejected code) waits for the next step, like the acceptance helper authflow.TOTP.
const lastStep = new Map<string, number>()

/** The RFC 6238 code (SHA-1, 30 s, 6 digits) of a hex-encoded key for the next unused time step. */
async function totp(hexKey: string): Promise<string> {
  let step = Math.floor(Date.now() / 30_000)
  const last = lastStep.get(hexKey) ?? -1
  if (step <= last) {
    await new Promise((resolve) => setTimeout(resolve, (last + 1) * 30_000 + 1_000 - Date.now()))
    step = Math.floor(Date.now() / 30_000)
  }
  lastStep.set(hexKey, step)
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(step))
  const sum = createHmac('sha1', Buffer.from(hexKey, 'hex')).update(msg).digest()
  const offset = sum[sum.length - 1] & 0x0f
  return String((sum.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}
