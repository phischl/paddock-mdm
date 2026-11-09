import { api, problemCode, type MaintenanceWindow, type MaintenanceWindowInput } from '../api/client'

const csrf = { 'X-Paddock-CSRF': '1' } as const

/** ISO weekdays, 1 = Monday to 7 = Sunday (plan M13c decision 4). */
export const isoWeekdays = [1, 2, 3, 4, 5, 6, 7] as const

/** Bounds of a window's length in minutes (plan M13c decision 4). */
export const minDurationMinutes = 30
export const maxDurationMinutes = 1440
const maxTimezoneLength = 64

/** The form's state: the start as HH:MM local time, the duration in minutes as typed. */
export interface WindowForm {
  days: number[]
  start: string
  duration: string
  timezone: string
}

export interface WindowErrors {
  days?: string
  start?: string
  duration?: string
  timezone?: string
}

/** HH:MM of minutes after midnight. */
export function minutesToClock(minutes: number): string {
  const h = Math.floor(minutes / 60)
  const m = minutes % 60
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0')
}

/** Minutes after midnight of HH:MM, or null when it is no valid time of day. */
export function clockToMinutes(text: string): number | null {
  const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(text.trim())
  return m ? Number(m[1]) * 60 + Number(m[2]) : null
}

/** The timezone names the browser knows, for the picker; empty when it cannot list them (the field stays free text). */
export function timezoneNames(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
  try {
    return intl.supportedValuesOf?.('timeZone') ?? []
  } catch {
    return []
  }
}

/** The browser's own timezone, the default of a new window. */
export function browserTimezone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
}

/** The form of a stored window, or of a new one (every weekday night from 22:00 for four hours in the browser's zone). */
export function windowForm(w: MaintenanceWindow | null): WindowForm {
  if (!w) return { days: [...isoWeekdays], start: '22:00', duration: '240', timezone: browserTimezone() }
  return { days: [...w.days], start: minutesToClock(w.start_minute), duration: String(w.duration_minutes), timezone: w.timezone }
}

/** Message keys of an invalid form; the server checks the timezone name against its own database. */
export function validateWindow(f: WindowForm): WindowErrors {
  const out: WindowErrors = {}
  if (f.days.length === 0 || f.days.some((d) => !Number.isInteger(d) || d < 1 || d > 7) || new Set(f.days).size !== f.days.length) {
    out.days = 'maintenanceWindow.daysRequired'
  }
  if (clockToMinutes(f.start) === null) out.start = 'maintenanceWindow.startInvalid'
  const duration = Number(f.duration.trim())
  if (!/^\d+$/.test(f.duration.trim()) || duration < minDurationMinutes || duration > maxDurationMinutes) {
    out.duration = 'maintenanceWindow.durationInvalid'
  }
  const tz = f.timezone.trim()
  if (tz === '' || tz.length > maxTimezoneLength) out.timezone = 'maintenanceWindow.timezoneInvalid'
  return out
}

/** The request body of a valid form. */
export function windowInput(f: WindowForm): MaintenanceWindowInput {
  return {
    days: [...f.days].sort((a, b) => a - b),
    start_minute: clockToMinutes(f.start) ?? 0,
    duration_minutes: Number(f.duration.trim()),
    timezone: f.timezone.trim(),
  }
}

/** The group's window, null when it has none, or the problem code. */
export async function getMaintenanceWindow(groupID: string): Promise<MaintenanceWindow | null | string> {
  const { data, error, response } = await api.GET('/api/v1/device-groups/{id}/maintenance-window', { params: { path: { id: groupID } } })
  if (data) return data
  // 404 is also the answer for a group without a window; the page loaded the group itself before.
  if (response.status === 404) return null
  return problemCode(error)
}

/** Sets or replaces the group's window; the stored window or the problem code. */
export async function setMaintenanceWindow(groupID: string, input: MaintenanceWindowInput): Promise<MaintenanceWindow | string> {
  const { data, error } = await api.PUT('/api/v1/device-groups/{id}/maintenance-window', {
    params: { path: { id: groupID }, header: csrf }, body: input,
  })
  return data ?? problemCode(error)
}

/** Removes the group's window; null or the problem code. */
export async function deleteMaintenanceWindow(groupID: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/device-groups/{id}/maintenance-window', { params: { path: { id: groupID }, header: csrf } })
  return error ? problemCode(error) : null
}
