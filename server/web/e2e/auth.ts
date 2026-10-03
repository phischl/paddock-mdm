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
  let next = new URL('/api/auth/login?return_to=%2F', baseURL()).toString()
  for (let hop = 0; hop < 30; hop++) {
    const url = new URL(next)
    if (url.hostname.startsWith('admin.') && url.pathname === '/api/auth/callback') {
      await page.goto(next)
      return
    }
    if (url.pathname.startsWith('/if/flow/')) {
      next = await runFlow(page, url, username, password(passwordFile))
      continue
    }
    const res = await page.request.get(next, { maxRedirects: 0 })
    const location = res.headers()['location']
    if (!location) throw new Error(`login: ${next} answered ${res.status()} without a redirect`)
    next = new URL(location, next).toString()
  }
  throw new Error('login: too many redirects')
}

async function runFlow(page: Page, flowPage: URL, username: string, secret: string): Promise<string> {
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
      default:
        throw new Error(`login: unexpected stage ${challenge.component} in flow ${slug}`)
    }
    const csrf = (await page.context().cookies(executor.origin)).find((c) => c.name === 'authentik_csrf')
    const res = await page.request.post(executor.toString(), {
      data: answer,
      headers: csrf ? { 'X-authentik-CSRF': csrf.value } : {},
    })
    challenge = await res.json()
  }
  throw new Error(`login: flow ${slug} did not finish`)
}

