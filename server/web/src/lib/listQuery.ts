import type { LocationQuery, LocationQueryRaw } from 'vue-router'

/** Items per page of every list (ADR 0018). */
export const pageSizes = [10, 25, 50, 100] as const
export type PageSize = (typeof pageSizes)[number]

/** page × page_size may not exceed this depth (ADR 0018). */
export const maxListDepth = 10000

/** Search text bounds of the list contract. */
export const minSearch = 2
export const maxSearch = 100

/** List state as kept in the URL query; filters are lists of values (repeatable query keys). */
export interface ListParams {
  page: number
  page_size: PageSize
  sort: string
  q?: string
  [filter: string]: unknown
}

/** One page of a list as the admin API returns it. */
export interface Page<T> {
  items: T[]
  page: number
  page_size: number
  total: number
  total_capped: boolean
  sort: string
}

/** A failed list request; code is the problem code. */
export class ListError extends Error {
  constructor(readonly code: string) {
    super(code)
  }
}

function first(value: LocationQuery[string] | undefined): string | undefined {
  const v = Array.isArray(value) ? value[0] : value
  return v ?? undefined
}

function all(value: LocationQuery[string] | undefined): string[] {
  if (value === undefined || value === null) return []
  return (Array.isArray(value) ? value : [value]).filter((v): v is string => typeof v === 'string' && v !== '')
}

/** Trimmed search text if it is within the contract's bounds, otherwise undefined. */
export function searchText(value: string | undefined | null): string | undefined {
  const text = (value ?? '').trim()
  const length = [...text].length
  return length >= minSearch && length <= maxSearch ? text : undefined
}

/**
 * Reads list state from the route query. Invalid values fall back to the defaults without error; sort must be one
 * of sortKeys (optionally prefixed with "-") when sortKeys is given. Filters become string lists.
 */
export function fromRouteQuery(
  q: LocationQuery,
  defaults: ListParams,
  filterKeys: string[],
  sortKeys: string[] = [],
): ListParams {
  const out: ListParams = { ...defaults }
  const size = Number(first(q.page_size))
  if ((pageSizes as readonly number[]).includes(size)) out.page_size = size as PageSize
  const page = Number(first(q.page))
  if (Number.isInteger(page) && page >= 1 && page * out.page_size <= maxListDepth) out.page = page
  const sort = first(q.sort)
  if (sort && (sortKeys.length === 0 || sortKeys.includes(sort.replace(/^-/, '')))) out.sort = sort
  const search = searchText(first(q.q))
  if (search) out.q = search
  for (const key of filterKeys) {
    const values = all(q[key])
    out[key] = values.length > 0 ? values : (defaults[key] ?? [])
  }
  return out
}

/** Writes list state to a route query; values equal to the defaults and empty filters are omitted. */
export function toRouteQuery(p: ListParams, defaults: ListParams): LocationQueryRaw {
  const out: LocationQueryRaw = {}
  for (const [key, value] of Object.entries(p)) {
    if (value === undefined || value === '' || JSON.stringify(value) === JSON.stringify(defaults[key])) continue
    if (Array.isArray(value)) {
      if (value.length > 0) out[key] = value.map(String)
    } else {
      out[key] = String(value)
    }
  }
  return out
}

/** A list column; title is a message key. */
export interface ListColumn {
  key: string
  title: string
  sortable?: boolean
}

/** An option of an enum filter; title is a message key, without one the value is shown as is. */
export interface ListFilterOption {
  value: string
  title?: string
}

/** Declarative filter of a list: a repeatable enum (multi-select) or a date range (two query keys). Labels are message keys. */
export type ListFilter =
  | { kind: 'enum'; key: string; label: string; options: ListFilterOption[] }
  | { kind: 'dateRange'; from: string; to: string; fromLabel: string; toLabel: string }

/** The query keys of the filters. */
export function filterKeys(filters: ListFilter[]): string[] {
  return filters.flatMap((f) => (f.kind === 'enum' ? [f.key] : [f.from, f.to]))
}

const dateInput = /^\d{4}-\d{2}-\d{2}$/

/** Drops filter values the definitions do not allow (unknown enum values, malformed dates, more than one date). */
export function sanitizeFilters(p: ListParams, filters: ListFilter[]): ListParams {
  const out = { ...p }
  for (const f of filters) {
    if (f.kind === 'enum') {
      const allowed = new Set(f.options.map((o) => o.value))
      out[f.key] = ((p[f.key] as string[] | undefined) ?? []).filter((v) => allowed.has(v))
    } else {
      for (const key of [f.from, f.to]) {
        const first = ((p[key] as string[] | undefined) ?? [])[0]
        out[key] = first && dateInput.test(first) ? [first] : []
      }
    }
  }
  return out
}
