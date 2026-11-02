import { defineStore } from 'pinia'
import { ref } from 'vue'
import { dismissKey } from '../lib/setupChecklist'

/**
 * Whether the setup checklist is dismissed on this browser (PDK-200). The state lives in localStorage per account;
 * every access may throw (private window, blocked site data), so the store keeps the value in memory as well and
 * the checklist works without storage.
 */
export const useSetupStore = defineStore('setup', () => {
  const dismissed = ref(false)
  let accountId = ''

  /** Reads the stored dismissal of the account once per account; a failing storage means not dismissed. */
  function load(id: string): void {
    if (id === accountId) return
    accountId = id
    try {
      dismissed.value = localStorage.getItem(dismissKey(id)) === '1'
    } catch {
      dismissed.value = false
    }
  }

  function set(value: boolean): void {
    dismissed.value = value
    if (!accountId) return
    try {
      if (value) localStorage.setItem(dismissKey(accountId), '1')
      else localStorage.removeItem(dismissKey(accountId))
    } catch {
      // The dismissal then only lasts for this page load.
    }
  }

  return { dismissed, load, dismiss: () => set(true), reopen: () => set(false) }
})
