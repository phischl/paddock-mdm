import { expect, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

/** Fails on serious or critical axe violations. */
export async function expectAccessible(page: Page): Promise<void> {
  // A loading list dims its rows and headers; axe would judge that transient state instead of the page.
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0)
  // Check the settled page: transitions (dialogs fading in) start a frame after the triggering click, so wait for
  // two frames, then for every finite animation; endless ones (loaders) never finish.
  await page.evaluate(async () => {
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))
    const finite = document.getAnimations().filter((a) => a.effect?.getComputedTiming().iterations !== Infinity)
    await Promise.all(finite.map((a) => a.finished.catch(() => undefined)))
  })
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze()
  const blocking = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
  expect(blocking.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([])
}

/** Records CSP violations reported by the browser. */
export function watchCSP(page: Page): string[] {
  const violations: string[] = []
  page.on('console', (msg) => {
    if (msg.type() === 'error' && /Content Security Policy/i.test(msg.text())) violations.push(msg.text())
  })
  return violations
}

/**
 * Checks an organization administrator's start page — the attention list while it has entries, otherwise the device
 * groups (plan M5b decision 11) — and opens the device groups.
 */
export async function expectAdminStartPage(page: Page): Promise<void> {
  const res = await page.request.get('/api/v1/attention?page_size=10')
  const open = ((await res.json()) as { total: number }).total
  await expect(page).toHaveURL(open > 0 ? /\/attention$/ : /\/device-groups$/)
  if (open > 0) await page.goto('/device-groups')
}
