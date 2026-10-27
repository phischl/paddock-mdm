import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api, type Me } from '../api/client'
import { applyLocale, type PortalLocale } from '../i18n'
import { applyTheme, isThemePreference, type ThemePreference } from '../lib/theme'

/** The role a role switch asks for (ADR 0045). */
export type RoleChoice = 'platform' | 'organization'

export const useSessionStore = defineStore('session', () => {
  const me = ref<Me | null>(null)
  const loading = ref<Promise<Me | null> | null>(null)

  const role = computed(() => me.value?.role ?? null)
  const isPlatform = computed(() => role.value === 'platform_admin')
  const canWrite = computed(() => role.value === 'org_admin' || role.value === 'org_operator')
  const canDelete = computed(() => role.value === 'org_admin')
  const canReadAudit = computed(() => role.value === 'org_admin' || role.value === 'org_auditor')
  const canReadGroups = computed(() => !!role.value && role.value !== 'platform_admin')
  /** The role this identity may switch to (ADR 0045 decision 3); null for single-role identities. */
  const alternateRole = computed(() => me.value?.alternate_role ?? null)

  function load(): Promise<Me | null> {
    if (me.value) return Promise.resolve(me.value)
    if (!loading.value) {
      loading.value = api.GET('/api/v1/me').then(({ data }) => {
        me.value = data ?? null
        if (me.value) {
          applyLocale(me.value.locale)
          applyTheme(me.value.theme)
        }
        return me.value
      })
    }
    return loading.value
  }

  /** Stores the administrator's language on the account and switches the portal to it; false if it failed. */
  async function setLocale(locale: PortalLocale): Promise<boolean> {
    const { data } = await api.PATCH('/api/v1/me', {
      params: { header: { 'X-Paddock-CSRF': '1' } },
      body: { locale },
    })
    if (!data) return false
    me.value = { ...data, step_up: me.value?.step_up }
    applyLocale(data.locale)
    return true
  }

  /** Stores the theme preference on the account and applies it; false if it failed (plan M7c decision 6). */
  async function setTheme(theme: ThemePreference): Promise<boolean> {
    if (!isThemePreference(theme)) return false
    const { data } = await api.PATCH('/api/v1/me', {
      params: { header: { 'X-Paddock-CSRF': '1' } },
      body: { theme },
    })
    if (!data) return false
    me.value = { ...data, step_up: me.value?.step_up }
    applyTheme(data.theme)
    return true
  }

  async function logout(): Promise<void> {
    const { data } = await api.POST('/api/auth/logout', { params: { header: { 'X-Paddock-CSRF': '1' } } })
    me.value = null
    window.location.assign(data?.end_session_url ?? '/')
  }

  /**
   * Starts the switch to the alternate role (ADR 0045 decision 3): the browser leaves for the identity provider and
   * returns with a new session. Rejects with the problem, without navigating, when the server refuses.
   */
  async function switchRole(choice: RoleChoice): Promise<void> {
    const { data, error } = await api.POST('/api/auth/switch', {
      params: { header: { 'X-Paddock-CSRF': '1' } },
      body: { role: choice },
    })
    if (!data) throw error ?? new Error('role switch failed')
    window.location.assign(data.authorize_url)
  }

  return {
    me, role, isPlatform, canWrite, canDelete, canReadAudit, canReadGroups, alternateRole,
    load, setLocale, setTheme, logout, switchRole,
  }
})
