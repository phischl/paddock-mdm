import { api, problemCode, type RecoveryExportRequest } from '../api/client'
import type { HeaderFile } from './disk'

/**
 * The encrypted recovery export of an organization during the grace period of its deletion (ADR 0052 amendment b):
 * every recovery key and local administrator password in one OpenPGP file, encrypted to the requester's public key or
 * passphrase. The passphrase lives only in the dialog's state and the request body; it is never stored.
 */

/** Bounds of the passphrase (plan M17 amendment b decision 22). */
export const minPassphrase = 16
export const maxPassphrase = 1024

/** The strength hint of a passphrase: too short, acceptable, or strong (24+ characters of three character classes). */
export type PassphraseStrength = 'short' | 'fair' | 'strong'

export function passphraseStrength(passphrase: string): PassphraseStrength {
  const length = [...passphrase].length
  if (length < minPassphrase) return 'short'
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(passphrase)).length
  return length >= 24 && classes >= 3 ? 'strong' : 'fair'
}

/** The validation message key of the dialog's input, or '' when it may be sent. */
export function validateExport(req: RecoveryExportRequest, repeat: string): string {
  if (req.recipient === 'public_key') {
    return req.public_key?.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----') ? '' : 'recoveryExport.errors.publicKey'
  }
  const passphrase = req.passphrase ?? ''
  if ([...passphrase].length < minPassphrase || [...passphrase].length > maxPassphrase) return 'recoveryExport.errors.length'
  return passphrase === repeat ? '' : 'recoveryExport.errors.mismatch'
}

/** The file name of a Content-Disposition header, or "paddock-recovery.asc". */
export function exportFileName(disposition: string | null): string {
  const match = /filename="?([^";]+)"?/.exec(disposition ?? '')
  return match?.[1] ?? 'paddock-recovery.asc'
}

/**
 * Requests the export of the administrator's own organization (organizationId null) or, for a platform
 * administrator, of the organization organizationId; returns the file, otherwise the problem code.
 */
export async function exportRecoveryKeys(organizationId: string | null, body: RecoveryExportRequest): Promise<HeaderFile | string> {
  const header = { 'X-Paddock-CSRF': '1' as const }
  const { data, error, response } = organizationId
    ? await api.POST('/api/platform/v1/organizations/{id}/recovery-export', {
      params: { path: { id: organizationId }, header }, body, parseAs: 'blob',
    })
    : await api.POST('/api/v1/recovery-export', { params: { header }, body, parseAs: 'blob' })
  if (error || !data) return problemCode(error)
  return { blob: data as Blob, filename: exportFileName(response.headers.get('Content-Disposition')) }
}
