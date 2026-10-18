import { api, problemCode, type LoginSettings, type LoginSettingsUpdate } from '../api/client'

/** Loads the login settings; the problem code on failure. */
export async function getLoginSettings(): Promise<LoginSettings | string> {
  const { data, error } = await api.GET('/api/v1/settings/login')
  return data ?? problemCode(error)
}

/** Replaces the login settings; the saved settings or the problem code. */
export async function saveLoginSettings(s: LoginSettingsUpdate): Promise<LoginSettings | string> {
  const { data, error } = await api.PUT('/api/v1/settings/login', { params: { header: { 'X-Paddock-CSRF': '1' } }, body: s })
  return data ?? problemCode(error)
}

/** Retention limits of the login history in days (server: loginsettings.Min/MaxLoginHistoryDays). */
export const minLoginHistoryDays = 7
export const maxLoginHistoryDays = 365

/** Whether the text of the retention field is a whole number of days the server accepts. */
export function validLoginHistoryDays(text: string): boolean {
  const days = Number(text)
  return text.trim() !== '' && Number.isInteger(days) && days >= minLoginHistoryDays && days <= maxLoginHistoryDays
}

/** List settings from a text area: one entry per line, blank lines ignored. */
export function lines(text: string): string[] {
  return text.split('\n').map((l) => l.trim()).filter((l) => l !== '')
}
