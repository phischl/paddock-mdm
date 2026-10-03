import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api, type Me } from '../api/client'

export const useSessionStore = defineStore('session', () => {
  const me = ref<Me | null>(null)
  const loading = ref<Promise<Me | null> | null>(null)

  const role = computed(() => me.value?.role ?? null)
  const isPlatform = computed(() => role.value === 'platform_admin')
  const canWrite = computed(() => role.value === 'org_admin' || role.value === 'org_operator')
  const canDelete = computed(() => role.value === 'org_admin')
  const canReadAudit = computed(() => role.value === 'org_admin' || role.value === 'org_auditor')
  const canReadGroups = computed(() => !!role.value && role.value !== 'platform_admin')

  function load(): Promise<Me | null> {
    if (me.value) return Promise.resolve(me.value)
    if (!loading.value) {
      loading.value = api.GET('/api/v1/me').then(({ data }) => {
        me.value = data ?? null
        return me.value
      })
    }
    return loading.value
  }

  async function logout(): Promise<void> {
    const { data } = await api.POST('/api/auth/logout', { params: { header: { 'X-Paddock-CSRF': '1' } } })
    me.value = null
    window.location.assign(data?.end_session_url ?? '/')
  }

  return { me, role, isPlatform, canWrite, canDelete, canReadAudit, canReadGroups, load, logout }
})
