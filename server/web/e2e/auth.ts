import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Page } from '@playwright/test'

const secrets = process.env.PADDOCK_E2E_SECRETS ?? '../../deploy/compose/.secrets'
const password = (file: string) => readFileSync(join(secrets, file), 'utf8').trim()
const baseURL = () => process.env.PADDOCK_E2E_BASE_URL ?? 'https://admin.paddock.localhost:8443'

/**
 * Signs in through Authentik's flow executor API — the same paddock-admin-login flow the Authentik login page
 * runs (development variant without MFA) — with the browser context's cookies, then opens the portal callback in
 * the browser. The Authentik UI itself is not under test.
 */
export async function login(page: Page, username: string, passwordFile: string): Promise<void> {
  await follow(page, new URL('/api/auth/login?return_to=%2F', baseURL()).toString(), '/api/auth/callback', username, password(passwordFile))
}

/**
 * Runs start, which makes the portal start a step-up (plan M4a decision 6), and completes it: the browser is kept
 * out of the paddock-stepup flow page (Authentik's UI would run the same flow), the flow is answered through the
 * executor API with the password and a TOTP code of the dev authenticator in totpKeyFile (devseed), then the
 * browser opens the step-up callback.
 */
export async function stepUp(page: Page, start: () => Promise<void>, username: string, passwordFile: string, totpKeyFile: string): Promise<void> {
  const flowPage = /\/if\/flow\/paddock-stepup\//
  await page.route(flowPage, (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '' }))
  const request = page.waitForRequest(flowPage)
  await start()
  const url = (await request).url()
  await page.unroute(flowPage)
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
        answer = { component: challenge.component, code: totp(totpKey) }
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

/** The current RFC 6238 code (SHA-1, 30 s, 6 digits) of a hex-encoded key. */
function totp(hexKey: string): string {
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const sum = createHmac('sha1', Buffer.from(hexKey, 'hex')).update(msg).digest()
  const offset = sum[sum.length - 1] & 0x0f
  return String((sum.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}
