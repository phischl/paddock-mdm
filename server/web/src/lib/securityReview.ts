import { api, problemCode, type SecurityReview } from '../api/client'

/** The review of existing data (ADR 0034 decision 7); a problem code when it cannot be read. */
export async function getSecurityReview(): Promise<SecurityReview | string> {
  const { data, error } = await api.GET('/api/v1/security-review')
  return data ?? problemCode(error)
}

/** What a confirmation of the review addresses. */
export interface ReviewConfirmation {
  kind: 'profile' | 'file'
  id: string
}

/** Confirms a root grant or a file on a sensitive path with the caller's step-up; null or a problem code. */
export async function confirmReviewItem(c: ReviewConfirmation): Promise<string | null> {
  const params = { path: { id: c.id }, header: { 'X-Paddock-CSRF': '1' as const } }
  const { error } = c.kind === 'profile'
    ? await api.POST('/api/v1/permission-profiles/{id}/confirm-root-grant', { params })
    : await api.POST('/api/v1/managed-files/{id}/confirm-sensitive', { params })
  return error ? problemCode(error) : null
}
