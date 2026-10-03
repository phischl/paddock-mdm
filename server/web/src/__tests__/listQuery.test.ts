import { describe, expect, it } from 'vitest'
import {
  fromRouteQuery, sanitizeFilters, searchText, toRouteQuery, type ListFilter, type ListParams,
} from '../lib/listQuery'

const defaults: ListParams = { page: 1, page_size: 25, sort: 'name', status: [] }
const filters: ListFilter[] = [
  { kind: 'enum', key: 'status', label: 'x', options: [{ value: 'active' }, { value: 'suspended' }] },
  { kind: 'dateRange', from: 'from', to: 'to', fromLabel: 'x', toLabel: 'x' },
]

describe('listQuery', () => {
  it('round-trips list state through the route query', () => {
    const state: ListParams = { page: 3, page_size: 10, sort: '-created_at', q: '50% off', status: ['active', 'suspended'] }
    const query = toRouteQuery(state, defaults)
    expect(query).toEqual({ page: '3', page_size: '10', sort: '-created_at', q: '50% off', status: ['active', 'suspended'] })
    expect(fromRouteQuery(query as never, defaults, ['status'], ['name', 'created_at'])).toEqual(state)
  })

  it('omits default values', () => {
    expect(toRouteQuery({ ...defaults }, defaults)).toEqual({})
    expect(toRouteQuery({ ...defaults, q: undefined, status: [] }, defaults)).toEqual({})
  })

  it('falls back to defaults for invalid values', () => {
    const invalid = { page: 'abc', page_size: '7', sort: 'description', q: 'a', status: '' }
    expect(fromRouteQuery(invalid, defaults, ['status'], ['name'])).toEqual(defaults)
    expect(fromRouteQuery({ page: '0' }, defaults, [], ['name']).page).toBe(1)
    expect(fromRouteQuery({ page: '2.5' }, defaults, [], ['name']).page).toBe(1)
    expect(fromRouteQuery({ page: '-1' }, defaults, [], ['name']).page).toBe(1)
    expect(fromRouteQuery({ sort: '--name' }, defaults, [], ['name']).sort).toBe('name')
    expect(fromRouteQuery({ q: 'x'.repeat(101) }, defaults, [], ['name']).q).toBeUndefined()
  })

  it('applies the depth limit to the page', () => {
    expect(fromRouteQuery({ page: '400', page_size: '25' }, defaults, [], []).page).toBe(400)
    expect(fromRouteQuery({ page: '401', page_size: '25' }, defaults, [], []).page).toBe(1)
    expect(fromRouteQuery({ page: '100', page_size: '100' }, defaults, [], []).page).toBe(100)
  })

  it('takes the first of repeated scalar keys', () => {
    expect(fromRouteQuery({ page: ['2', '3'], sort: ['-name', 'name'] }, defaults, [], ['name'])).toMatchObject({ page: 2, sort: '-name' })
  })

  it('trims search text and enforces its bounds', () => {
    expect(searchText('  lap  ')).toBe('lap')
    expect(searchText(' a ')).toBeUndefined()
    expect(searchText('')).toBeUndefined()
    expect(searchText(null)).toBeUndefined()
    expect(searchText('äö')).toBe('äö')
  })

  it('drops filter values the definitions do not allow', () => {
    const p = sanitizeFilters({ ...defaults, status: ['active', 'deleted'], from: ['2026-01-01', '2026-02-01'], to: ['tomorrow'] }, filters)
    expect(p.status).toEqual(['active'])
    expect(p.from).toEqual(['2026-01-01'])
    expect(p.to).toEqual([])
  })
})
