import { api, problemCode } from '../api/client'

/** The text a platform administrator types to confirm ending every session. */
export const endAllConfirmation = 'END'

/** Ends every portal session (plan M8s decision 16); the new generation on success, otherwise the problem code. */
export async function endAllSessions(): Promise<number | string> {
  const { data, error } = await api.POST('/api/platform/v1/sessions/end-all', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
  })
  return data ? data.generation : problemCode(error)
}
