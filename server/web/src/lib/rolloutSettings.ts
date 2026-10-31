import { api, problemCode, type RolloutSettings, type RolloutSettingsUpdate } from '../api/client'

const csrf = { 'X-Paddock-CSRF': '1' } as const

/** Limits of the settings (server: domain/configrollout). The server also enforces a minimum wave duration of 15 minutes. */
export const maxWaves = 10
export const minWaveMinutesProduction = 15
export const minWaveMinutesDevelopment = 1

/** The rollout settings of the organization (plan M11 decision 24). */
export async function getRolloutSettings(): Promise<RolloutSettings | string> {
  const { data, error } = await api.GET('/api/v1/settings/rollout')
  return data ?? problemCode(error)
}

/** Replaces the rollout settings; the saved settings or the problem code. */
export async function saveRolloutSettings(s: RolloutSettingsUpdate): Promise<RolloutSettings | string> {
  const { data, error } = await api.PUT('/api/v1/settings/rollout', { params: { header: csrf }, body: s })
  return data ?? problemCode(error)
}

/** The waves as the text field shows them: "1, 10, 50, 100". */
export function formatWaves(waves: number[]): string {
  return waves.join(', ')
}

/** Parses the waves text; null when an entry is not a whole number. */
export function parseWaves(text: string): number[] | null {
  const parts = text.split(',').map((p) => p.trim())
  if (parts.length === 0 || parts.some((p) => !/^\d+$/.test(p))) return null
  return parts.map(Number)
}

/** Whether the waves are valid (the server's rule, domain/configrollout ValidateWaves). */
export function validWaves(waves: number[] | null): boolean {
  if (!waves || waves.length === 0 || waves.length > maxWaves || waves[waves.length - 1] !== 100) return false
  return waves.every((p, i) => p >= 1 && p <= 100 && (i === 0 || p > waves[i - 1]))
}

export interface RolloutErrors {
  waves?: string
  min_wave_minutes?: string
  failure_threshold_percent?: string
  failure_threshold_min?: string
}

/** Message keys of invalid settings; wavesText is the text of the waves field. */
export function validateRolloutSettings(s: RolloutSettingsUpdate, wavesText: string): RolloutErrors {
  const out: RolloutErrors = {}
  if (!validWaves(parseWaves(wavesText))) out.waves = 'rolloutSettings.wavesInvalid'
  if (!Number.isInteger(s.min_wave_minutes) || s.min_wave_minutes < 1) out.min_wave_minutes = 'rolloutSettings.minWaveInvalid'
  if (!Number.isInteger(s.failure_threshold_percent) || s.failure_threshold_percent < 0 || s.failure_threshold_percent > 100) {
    out.failure_threshold_percent = 'rolloutSettings.thresholdPercentInvalid'
  }
  if (!Number.isInteger(s.failure_threshold_min) || s.failure_threshold_min < 0) out.failure_threshold_min = 'rolloutSettings.thresholdMinInvalid'
  return out
}
