import { ref } from 'vue'
import { api, problemCode, type AuditEvent } from '../api/client'
import { dateInputToRFC3339, toDateInput } from './format'

/** Codes offered in the filter (the closed registry, server/internal/domain/audit/codes.go). */
export const auditCodes = [
  'admin.login',
  'device_group.created',
  'device_group.updated',
  'device_group.deleted',
  'organization.created',
] as const

export function useAuditLog() {
  const items = ref<AuditEvent[]>([])
  const page = ref(1)
  const hasMore = ref(false)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const today = new Date()
  const from = ref(toDateInput(new Date(today.getFullYear(), today.getMonth(), today.getDate() - 6)))
  const to = ref(toDateInput(today))
  const code = ref<string>('')

  async function load(more = false): Promise<void> {
    loading.value = true
    error.value = null
    const { data, error: err } = await api.GET('/api/v1/audit-events', {
      params: {
        query: {
          from: dateInputToRFC3339(from.value, false),
          to: dateInputToRFC3339(to.value, true),
          code: code.value ? [code.value] : undefined,
          page: more ? page.value + 1 : 1,
          page_size: 100,
        },
      },
    })
    loading.value = false
    if (err || !data) {
      error.value = problemCode(err)
      return
    }
    items.value = more ? [...items.value, ...data.items] : data.items
    page.value = data.page
    hasMore.value = data.page * data.page_size < data.total
  }

  return { items, hasMore, loading, error, from, to, code, load }
}
