import { expect, test as base, type APIRequestContext } from '@playwright/test'

const csrf = { 'X-Paddock-CSRF': '1' }
const tokens = '/api/v1/enrollment-tokens'
// API tokens are revoked, never deleted; a test may have revoked one itself (409 invalid_state).
const apiTokens = '/api/v1/api-tokens'
// Removing an IP allow list entry may need a confirmation (plan M7a decision 12): disable for the last entry,
// lockout for the test's own address.
const ipAllowlist = '/api/platform/v1/ip-allowlist'

/**
 * Test data hygiene (plan M2.2 decision 7): what a test creates is removed through the admin API when the test ends,
 * also after a failure, with the test's signed-in session.
 */
export interface Cleanup {
  /**
   * Removes every item of collection (e.g. /api/v1/device-groups) that the search q finds: deletes device groups,
   * managed files and units, revokes enrollment and API tokens (they cannot be deleted). q must be unique to the test.
   * Removals run in reverse order of registration.
   */
  remove(collection: string, q: string): void
}

/** `test` with the `cleanup` fixture. */
export const test = base.extend<{ cleanup: Cleanup }>({
  cleanup: async ({ page }, use) => {
    const searches: [string, string][] = []
    await use({ remove: (collection, q) => { searches.push([collection, q]) } })
    for (const [collection, q] of searches.reverse()) await removeFound(page.request, collection, q)
  },
})

async function removeFound(request: APIRequestContext, collection: string, q: string): Promise<void> {
  const res = await request.get(`${collection}?page_size=100&q=${encodeURIComponent(q)}`)
  expect(res.status(), `cleanup: search ${collection} for ${q}`).toBe(200)
  const { items, total } = (await res.json()) as { items: { id: string }[]; total: number }
  expect(total, `cleanup: ${collection} finds more than one page for ${q}`).toBe(items.length)
  for (const { id } of items) {
    if (collection === apiTokens) {
      const revoked = await request.post(`${collection}/${id}/revoke`, { headers: csrf })
      expect([200, 409], `cleanup: revoke ${collection}/${id}`).toContain(revoked.status())
      continue
    }
    if (collection === ipAllowlist) {
      let removed = await request.delete(`${collection}/${id}?confirm=disable`, { headers: csrf })
      if (removed.status() === 409) removed = await request.delete(`${collection}/${id}?confirm=lockout`, { headers: csrf })
      expect(removed.status(), `cleanup: remove ${collection}/${id}`).toBe(204)
      continue
    }
    const removed = collection === tokens
      ? await request.post(`${collection}/${id}/revoke`, { headers: csrf })
      : await request.delete(`${collection}/${id}`, { headers: csrf })
    expect(removed.status(), `cleanup: remove ${collection}/${id}`).toBe(collection === tokens ? 200 : 204)
  }
}
