import { ref } from 'vue'
import { api, problemCode, type Organization } from '../api/client'

export function useOrganizations() {
  const items = ref<Organization[]>([])
  const nextCursor = ref<string | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function load(more = false): Promise<void> {
    loading.value = true
    error.value = null
    const { data, error: err } = await api.GET('/api/platform/v1/organizations', {
      params: { query: { limit: 50, cursor: more && nextCursor.value ? nextCursor.value : undefined } },
    })
    loading.value = false
    if (err || !data) {
      error.value = problemCode(err)
      return
    }
    items.value = more ? [...items.value, ...data.items] : data.items
    nextCursor.value = data.next_cursor
  }

  async function create(slug: string, name: string): Promise<string | null> {
    const { error: err } = await api.POST('/api/platform/v1/organizations', {
      params: { header: { 'X-Paddock-CSRF': '1' } },
      body: { slug: slug.trim(), name: name.trim() },
    })
    await load()
    return err ? problemCode(err) : null
  }

  return { items, nextCursor, loading, error, load, create }
}
