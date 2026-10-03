import { ref } from 'vue'
import { api, problemCode, type DeviceGroup } from '../api/client'

/** State and actions of the device group page. */
export function useDeviceGroups() {
  const items = ref<DeviceGroup[]>([])
  const nextCursor = ref<string | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function load(more = false): Promise<void> {
    loading.value = true
    error.value = null
    const { data, error: err } = await api.GET('/api/v1/device-groups', {
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

  /** Returns null on success, otherwise the problem code. */
  async function create(name: string, description: string): Promise<string | null> {
    const { error: err } = await api.POST('/api/v1/device-groups', {
      params: { header: { 'X-Paddock-CSRF': '1' } },
      body: { name: name.trim(), description: description.trim() },
    })
    if (err) return problemCode(err)
    await load()
    return null
  }

  async function update(id: string, name: string, description: string): Promise<string | null> {
    const { error: err } = await api.PATCH('/api/v1/device-groups/{id}', {
      params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
      body: { name: name.trim(), description: description.trim() },
    })
    if (err) return problemCode(err)
    await load()
    return null
  }

  async function remove(id: string): Promise<string | null> {
    const { error: err } = await api.DELETE('/api/v1/device-groups/{id}', {
      params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    })
    if (err) return problemCode(err)
    await load()
    return null
  }

  return { items, nextCursor, loading, error, load, create, update, remove }
}
