import { expect, test as base, type APIRequestContext } from '@playwright/test'

const csrf = { 'X-Paddock-CSRF': '1' }
const tokens = '/api/v1/enrollment-tokens'

/**
 * Test data hygiene (plan M2.2 decision 7): what a test creates is removed through the admin API when the test ends,
 * also after a failure, with the test's signed-in session.
 */
export interface Cleanup {
  /**
   * Removes every item of collection (e.g. /api/v1/device-groups) that the search q finds: deletes device groups,
   * managed files and units, revokes enrollment tokens (they cannot be deleted). q must be unique to the test.
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
    const removed = collection === tokens
      ? await request.post(`${collection}/${id}/revoke`, { headers: csrf })
      : await request.delete(`${collection}/${id}`, { headers: csrf })
    expect(removed.status(), `cleanup: remove ${collection}/${id}`).toBe(collection === tokens ? 200 : 204)
  }
}
