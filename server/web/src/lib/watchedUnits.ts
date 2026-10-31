import { api, problemCode } from '../api/client'

/** The most units an organization can watch (plan M9 decision 38). */
export const maxWatchedUnits = 32

/** The watched third-party units of the presence policy; null updatedAt for an empty list. */
export interface WatchedUnits {
  units: string[]
  updatedAt: string | null
}

/** The watched units, or a problem code when they cannot be read. */
export async function getWatchedUnits(): Promise<WatchedUnits | string> {
  const { data, error } = await api.GET('/api/v1/settings/watched-units')
  return data ? { units: data.units, updatedAt: data.updated_at ?? null } : problemCode(error)
}

/** Replaces the watched units (organization administrator with a step-up); the saved list or a problem code. */
export async function setWatchedUnits(units: string[]): Promise<WatchedUnits | string> {
  const { data, error } = await api.PUT('/api/v1/settings/watched-units', {
    params: { header: { 'X-Paddock-CSRF': '1' } }, body: { units },
  })
  return data ? { units: data.units, updatedAt: data.updated_at ?? null } : problemCode(error)
}

/** A validation problem of a unit list: the message key and its values, or null when the list can be saved. */
export interface UnitsProblem {
  key: 'watchedUnits.errors.notService' | 'watchedUnits.errors.duplicate' | 'watchedUnits.errors.tooMany'
  values: Record<string, string | number>
}

/** Checks a unit list the way the server does for the rules a browser can know (suffix, duplicates, count). */
export function validateWatchedUnits(units: string[]): UnitsProblem | null {
  if (units.length > maxWatchedUnits) return { key: 'watchedUnits.errors.tooMany', values: { max: maxWatchedUnits } }
  const seen = new Set<string>()
  for (const u of units) {
    if (!/^[a-zA-Z0-9@._-]+\.service$/.test(u)) return { key: 'watchedUnits.errors.notService', values: { unit: u } }
    if (seen.has(u)) return { key: 'watchedUnits.errors.duplicate', values: { unit: u } }
    seen.add(u)
  }
  return null
}
