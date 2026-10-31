import { api, problemCode, type PrivacySettings, type PrivacySettingsUpdate } from '../api/client'

const csrf = { 'X-Paddock-CSRF': '1' } as const

/** The bounds of retired_inventory_days (plan M10 §6.1, the server's rule). */
export const retiredInventoryDaysMin = 1
export const retiredInventoryDaysMax = 365

/** The privacy settings of the organization (ADR 0032 §2, plan M10 decision 10). */
export async function getPrivacySettings(): Promise<PrivacySettings | string> {
  const { data, error } = await api.GET('/api/v1/settings/privacy')
  return data ?? problemCode(error)
}

/** Replaces the privacy settings; the saved settings or the problem code. */
export async function savePrivacySettings(s: PrivacySettingsUpdate): Promise<PrivacySettings | string> {
  const { data, error } = await api.PUT('/api/v1/settings/privacy', { params: { header: csrf }, body: s })
  return data ?? problemCode(error)
}

/** Whether a number of days is a valid retired_inventory_days. */
export function validRetiredInventoryDays(days: number): boolean {
  return Number.isInteger(days) && days >= retiredInventoryDaysMin && days <= retiredInventoryDaysMax
}
