import type { AuditEvent } from '../api/client'

/** Formats an RFC 3339 timestamp in the browser's time zone. */
export function formatDateTime(iso: string, locale: string): string {
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(iso))
}

type Translate = (key: string, values?: Record<string, unknown>) => string
type Exists = (key: string) => boolean

/**
 * Renders an audit event from the message key audit.<code> with its params. Events themselves are never
 * translated or rewritten; unknown codes or incomplete params fall back to the raw code.
 */
export function auditText(t: Translate, te: Exists, ev: AuditEvent): string {
  const key = 'audit.' + ev.code
  if (!te(key)) return ev.code
  const values: Record<string, unknown> = {
    ...ev.params,
    actor: ev.actor.display ?? ev.actor.type,
    target: ev.target?.display ?? ev.target?.id ?? '',
  }
  if (values.name === undefined) values.name = ev.target?.display ?? ''
  if (values.slug === undefined) values.slug = ev.target?.display ?? ''
  if (values.hostname === undefined) values.hostname = ev.target?.display ?? ev.target?.id ?? ''
  try {
    return t(key, values)
  } catch {
    return ev.code
  }
}

/** Converts a date input value (YYYY-MM-DD, local) to RFC 3339 at local midnight; end=true takes the next midnight. */
export function dateInputToRFC3339(value: string, end: boolean): string | undefined {
  if (!value) return undefined
  const [y, m, d] = value.split('-').map(Number)
  const date = new Date(y, m - 1, d + (end ? 1 : 0))
  return date.toISOString()
}

export function toDateInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}
