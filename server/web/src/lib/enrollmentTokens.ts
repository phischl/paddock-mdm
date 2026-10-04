import { api, listPage, problemCode, type EnrollmentToken, type EnrollmentTokenCreated, type EnrollmentTokenSort } from '../api/client'
import type { ListParams, Page } from './listQuery'

/** One page of enrollment tokens for DataList. */
export async function listEnrollmentTokens(p: ListParams): Promise<Page<EnrollmentToken>> {
  return listPage(
    await api.GET('/api/v1/enrollment-tokens', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as EnrollmentTokenSort, q: p.q } },
    }),
  )
}

export interface TokenInput {
  name: string
  validDays: number
  maxUses: number
  groupID: string | null
  autoApprove: boolean
}

/** Validity choices in days (at most 30, plan M2a decision 9). */
export const validityDays = [1, 7, 14, 30] as const

/** Creates a token; returns the one-time answer or the problem code. */
export async function createEnrollmentToken(input: TokenInput, now = new Date()): Promise<EnrollmentTokenCreated | string> {
  const expires = new Date(now.getTime() + input.validDays * 24 * 60 * 60 * 1000)
  const { data, error } = await api.POST('/api/v1/enrollment-tokens', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: {
      name: input.name.trim(), expires_at: expires.toISOString(), max_uses: input.maxUses, auto_approve: input.autoApprove,
      ...(input.groupID ? { device_group_id: input.groupID } : {}),
    },
  })
  return data ?? problemCode(error)
}

/** Revokes a token; null on success, otherwise the problem code. */
export async function revokeEnrollmentToken(id: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/enrollment-tokens/{id}:revoke', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return error ? problemCode(error) : null
}

/** The enrollment configuration as the device expects it in /etc/paddock (pretty JSON). */
export function configText(created: EnrollmentTokenCreated): string {
  return JSON.stringify(created.enrollment_config, null, 2)
}
