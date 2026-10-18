import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp, VPagination, VSelect } from 'vuetify/components'
import DataList from '../components/DataList.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { ListError, type ListColumn, type ListFilter, type ListParams, type Page } from '../lib/listQuery'

interface Row {
  id: string
  name: string
  status: string
}

const columns: ListColumn[] = [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'status', title: 'organizations.status', sortable: true },
]
const filters: ListFilter[] = [
  {
    kind: 'enum', key: 'status', label: 'organizations.status',
    options: [{ value: 'active', title: 'organizations.statuses.active' }, { value: 'suspended', title: 'organizations.statuses.suspended' }],
  },
]

function rows(n: number): Row[] {
  return Array.from({ length: n }, (_, i) => ({ id: String(i), name: `Group ${i}`, status: 'active' }))
}

function pageOf(p: ListParams, total: number, capped = false): Page<Row> {
  const count = Math.max(0, Math.min(p.page_size, total - (p.page - 1) * p.page_size))
  return { items: rows(count), page: p.page, page_size: p.page_size, total, total_capped: capped, sort: p.sort }
}

let wrapper: VueWrapper | null = null

/** Resolves after the next completed navigation (the list writes its state with router.replace). */
function navigated(router: Router): Promise<void> {
  return new Promise((resolve) => {
    const stop = router.afterEach(() => {
      stop()
      resolve()
    })
  })
}

afterEach(() => {
  vi.useRealTimers()
  wrapper?.unmount()
  wrapper = null
  resize(1280)
})

const listEvent = (action: 'down' | 'up' | 'open') => window.dispatchEvent(new CustomEvent('paddock:list', { detail: action }))

function resize(width: number): void {
  Object.defineProperty(window, 'innerWidth', { value: width, configurable: true, writable: true })
  window.dispatchEvent(new Event('resize'))
}

async function mountList(
  url: string,
  fetch: (p: ListParams) => Promise<Page<Row>>,
  onRowClick?: (item: Row) => void,
  extra: Record<string, unknown> = {},
  slots: Record<string, (p: { item: Row }) => unknown> = {},
): Promise<{ router: Router; w: VueWrapper }> {
  const Page = () =>
    h(DataList<Row>, { columns, filters, fetch, searchable: true, defaultSort: 'name', itemValue: 'id', onRowClick, ...extra }, slots)
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/list', name: 'list', component: Page }] })
  await router.push(url)
  await router.isReady()
  // Vuetify components need a v-app ancestor.
  const App = () => h(VApp, null, { default: () => h(RouterView) })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router] }, attachTo: document.body })
  await flushPromises()
  return { router, w: wrapper }
}

describe('DataList', () => {
  it('shows the hint of a filter below it while the filter has the focus', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 1)))
    const { w } = await mountList('/list', fetch, undefined, { filters: [{ ...filters[0], hint: 'devices.contactHint' }] })
    const filter = w.get('[data-testid="list-filter-status"]')
    expect(filter.text()).not.toContain('Online: a check-in within the last 15 minutes.')
    await filter.get('input').trigger('focus')
    expect(filter.text()).toContain('Online: a check-in within the last 15 minutes.')
    const describedBy = filter.get('input').attributes('aria-describedby')
    expect(document.getElementById(describedBy!)?.textContent).toContain('Online: a check-in within the last 15 minutes.')
  })

  it('reads the list state from the URL', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 95)))
    const { w } = await mountList('/list?page=2&page_size=10&sort=-status&q=lap&status=suspended', fetch)
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0][0]).toEqual({ page: 2, page_size: 10, sort: '-status', q: 'lap', status: ['suspended'] })
    expect(w.find('[data-testid="list-range"]').text()).toBe('11–20 of 95 results')
    expect((w.find('[data-testid="list-search"] input').element as HTMLInputElement).value).toBe('lap')
  })

  it('falls back to defaults for invalid query values without an error', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 3)))
    const { w } = await mountList('/list?page=abc&page_size=7&sort=nope&q=a&status=bogus', fetch)
    expect(fetch.mock.calls[0][0]).toEqual({ page: 1, page_size: 25, sort: 'name', status: [] })
    expect(w.find('[role="alert"]').exists()).toBe(false)
  })

  it('debounces the search by 300 ms and starts again at page 1', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 95)))
    const { router, w } = await mountList('/list?page=3&page_size=10', fetch)
    const input = w.find('[data-testid="list-search"] input')
    const replace = vi.spyOn(router, 'replace')
    // Only the timeout clock is faked: Vue, the router and flushPromises keep their real microtask and setImmediate
    // scheduling, so the test advances exactly the clock the debounce uses and does not depend on wall-clock precision.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    await input.setValue('la')
    await vi.advanceTimersByTimeAsync(100)
    await input.setValue('lap')
    // At 299 ms after the last keystroke nothing has been searched, and the timer for "la" (due at 200 ms) was cancelled.
    await vi.advanceTimersByTimeAsync(299)
    expect(replace).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(replace).toHaveBeenCalledTimes(1)
    expect(replace.mock.calls[0][0]).toEqual({ query: { page_size: '10', q: 'lap' } })
    // Vuetify's back-button guard holds the navigation on a 0 ms timeout, which fake timers schedule 1 ms later when it
    // is created inside a tick.
    await vi.advanceTimersByTimeAsync(1)
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ page_size: '10', q: 'lap' })
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(fetch.mock.calls[1][0]).toMatchObject({ page: 1, q: 'lap' })
  })

  it('starts again at page 1 on sort, filter and page size changes, but not on paging', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 95)))
    const { router, w } = await mountList('/list?page=3&page_size=10', fetch)

    let done = navigated(router)
    await w.findAll('th').find((th) => th.text().includes('Name'))!.trigger('click')
    await done
    expect(router.currentRoute.value.query).toEqual({ page_size: '10', sort: '-name' })

    await router.replace('/list?page=3&page_size=10')
    done = navigated(router)
    w.findAllComponents(VSelect).find((s) => s.attributes('data-testid') === 'list-filter-status')!.vm.$emit('update:modelValue', ['active'])
    await done
    expect(router.currentRoute.value.query).toEqual({ page_size: '10', status: ['active'] })

    await router.replace('/list?page=3&page_size=10')
    done = navigated(router)
    w.findAllComponents(VSelect).find((s) => s.attributes('data-testid') === 'list-page-size')!.vm.$emit('update:modelValue', 50)
    await done
    expect(router.currentRoute.value.query).toEqual({ page_size: '50' })

    await router.replace('/list?page=3&page_size=10')
    done = navigated(router)
    w.findComponent(VPagination).vm.$emit('update:modelValue', 7)
    await done
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ page: '7', page_size: '10' })
    expect(fetch.mock.lastCall![0]).toMatchObject({ page: 7, page_size: 10 })
  })

  it('shows page numbers', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 95)))
    const { w } = await mountList('/list?page_size=10', fetch)
    const pagination = w.find('[data-testid="list-pagination"]')
    expect(pagination.exists()).toBe(true)
    expect(pagination.text()).toContain('10')
    expect(pagination.find('[aria-current="true"]').text()).toBe('1')
  })

  it('shows 10,000+ and a hint when the total is capped', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 10000, true)))
    const { w } = await mountList('/list', fetch)
    expect(w.find('[data-testid="list-range"]').text()).toBe('1–25 of 10,000+ results')
    expect(w.find('[role="status"]').text()).toContain('More than 10,000 results match')
  })

  it('emits row-click only when the page listens', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 3)))
    const clicked = vi.fn()
    const { w } = await mountList('/list', fetch, clicked)
    expect(w.find('tbody tr').classes()).toContain('v-data-table__tr--clickable')
    await w.findAll('tbody tr')[1].trigger('click')
    expect(clicked).toHaveBeenCalledWith({ id: '1', name: 'Group 1', status: 'active' })
    w.unmount()
    const { w: plain } = await mountList('/list', fetch)
    expect(plain.find('tbody tr').classes()).not.toContain('v-data-table__tr--clickable')
  })

  it('shows the problem of a failed request', async () => {
    const fetch = vi.fn(() => Promise.reject(new ListError('forbidden')))
    const { w } = await mountList('/list', fetch)
    expect(w.find('p[role="alert"]').text()).toBe('You are not allowed to do this.')
  })

  it('marks the table busy and names the loading bar while a request runs', async () => {
    let resolve: (page: Page<Row>) => void = () => undefined
    const fetch = vi.fn(() => new Promise<Page<Row>>((r) => { resolve = r }))
    const { w } = await mountList('/list', fetch)
    expect(w.find('.table').attributes('aria-busy')).toBe('true')
    expect(w.find('.table [role="progressbar"][aria-hidden="false"]').attributes('aria-label')).toBe('Loading results')
    resolve(pageOf({ page: 1, page_size: 25, sort: 'name' }, 3))
    await flushPromises()
    expect(w.find('.table').attributes('aria-busy')).toBe('false')
  })

  it('prefixes its query keys so two lists share a page', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 95)))
    const { router, w } = await mountList('/list?pane.page=2&pane.q=lap&page=4&other=x', fetch, undefined, { queryPrefix: 'pane' })
    expect(fetch.mock.calls[0][0]).toMatchObject({ page: 2, q: 'lap' })
    const done = navigated(router)
    await w.findAll('th').find((th) => th.text().includes('Name'))!.trigger('click')
    await done
    expect(router.currentRoute.value.query).toEqual({ 'pane.q': 'lap', 'pane.sort': '-name', page: '4', other: 'x' })
  })

  it('renders cards with the primary, status and meta cells below 600 px and the filters in a sheet', async () => {
    resize(390)
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 3)))
    const { w } = await mountList('/list?status=active', fetch, undefined, {
      columns: [
        { key: 'name', title: 'common.name', role: 'primary', mono: true },
        { key: 'status', title: 'organizations.status', role: 'status' },
        { key: 'id', title: 'devices.id', role: 'meta' },
      ],
    }, { 'item.status': ({ item }) => h('span', { class: 'chip' }, item.status) })
    expect(w.find('table').exists()).toBe(false)
    const cards = w.findAll('.pd-card')
    expect(cards.length).toBe(3)
    expect(cards[1].find('.pd-card-primary').text()).toBe('Group 1')
    expect(cards[1].find('.pd-card-primary').classes()).toContain('pd-cell-mono')
    expect(cards[1].find('.pd-card-status .chip').text()).toBe('active')
    expect(cards[1].find('.pd-card-meta').text()).toBe('Device ID: 1')
    expect(cards[1].attributes('tabindex')).toBe('-1')
    expect(w.find('[data-testid="list-search"]').exists()).toBe(true)
    expect(w.find('[data-testid="list-filter-status"]').exists()).toBe(false)
    expect(w.find('[data-testid="list-filters-open"]').text()).toBe('Filters (1)')
    await w.find('[data-testid="list-filters-open"]').trigger('click')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="list-filter-sheet"]')).not.toBeNull())
    expect(document.querySelector('[data-testid="list-filter-sheet"] [data-testid="list-filter-status"]')).not.toBeNull()
  })

  it('forces the cards layout on request and keeps the cell slots', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 2)))
    const { w } = await mountList('/list', fetch, undefined, { layout: 'cards', currentValue: '1' }, {
      'item.name': ({ item }) => h('a', { href: '/x/' + item.id }, item.name),
    })
    expect(w.findAll('.pd-card').length).toBe(2)
    expect(w.find('.pd-card a').attributes('href')).toBe('/x/0')
    expect(w.findAll('.pd-card')[1].attributes('aria-current')).toBe('true')
    expect(w.findAll('.pd-card')[0].attributes('aria-current')).toBeUndefined()
  })

  it('moves a row cursor with j/k, opens with Enter, and leaves the keys to an input that has the focus', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 3)))
    const clicked = vi.fn()
    const { w } = await mountList('/list', fetch, clicked)
    const rows = () => w.findAll('tbody tr[data-row-index]')
    expect(rows().length).toBe(3)
    expect(rows()[0].attributes('tabindex')).toBe('-1')
    listEvent('down')
    await flushPromises()
    expect(rows()[0].classes()).toContain('pd-row-cursor')
    expect(document.activeElement).toBe(rows()[0].element)
    listEvent('down')
    listEvent('down')
    listEvent('down')
    await flushPromises()
    expect(rows()[2].classes()).toContain('pd-row-cursor')
    listEvent('up')
    await flushPromises()
    expect(rows()[1].classes()).toContain('pd-row-cursor')
    listEvent('open')
    expect(clicked).toHaveBeenCalledWith({ id: '1', name: 'Group 1', status: 'active' })
    // A click sets the cursor too.
    await rows()[0].trigger('click')
    expect(rows()[0].classes()).toContain('pd-row-cursor')
  })

  it('follows the first link of the cursor row when the page does not listen', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 2)))
    const followed = vi.fn()
    const { w } = await mountList('/list', fetch, undefined, {}, {
      'item.name': ({ item }) => h('a', { href: '#' + item.id, onClick: (e: Event) => { e.preventDefault(); followed(item.id) } }, item.name),
    })
    listEvent('down')
    listEvent('down')
    listEvent('open')
    await flushPromises()
    expect(followed).toHaveBeenCalledWith('1')
    expect(w.findAll('tbody tr[data-row-index]')[1].classes()).toContain('pd-row-cursor')
  })

  it('offers to clear the filters when nothing matches, and an empty state otherwise', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 0)))
    const { router, w } = await mountList('/list?q=lap&status=active', fetch, undefined, {
      emptyTitle: 'deviceGroups.empty.title', emptyDescription: 'deviceGroups.empty.description',
    })
    expect(w.find('.pd-list-empty').text()).toContain('No results match the search or filters.')
    const done = navigated(router)
    await w.find('[data-testid="list-clear-filters"]').trigger('click')
    await done
    expect(router.currentRoute.value.query).toEqual({})
    await flushPromises()
    expect(w.find('[data-testid="empty-state"]').exists()).toBe(true)
    expect(w.find('[data-testid="list-clear-filters"]').exists()).toBe(false)
  })

  it('shows the empty state below the column headers without an empty table row above it', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 0)))
    const { w } = await mountList('/list', fetch, undefined, { emptyTitle: 'deviceGroups.empty.title' })
    const table = w.get('table')
    expect(table.findAll('thead th').map((th) => th.text())).toEqual(['Name', 'Status'])
    expect(table.findAll('tbody tr')).toHaveLength(0)
    expect(w.get('[data-testid="empty-state"]').text()).toContain('No device groups yet')
  })

  it('toggles an expanded row with a labelled button', async () => {
    const fetch = vi.fn((p: ListParams) => Promise.resolve(pageOf(p, 2)))
    const { w } = await mountList('/list', fetch, undefined, { expandable: true }, {
      expanded: ({ item }) => h('dl', { class: 'details' }, item.id),
    })
    const toggles = () => w.findAll('[data-testid="list-expand"]')
    expect(toggles().length).toBe(2)
    expect(toggles()[1].attributes('aria-label')).toBe('Show details of row 2')
    expect(toggles()[1].attributes('aria-expanded')).toBe('false')
    expect(w.find('.details').exists()).toBe(false)
    await toggles()[1].trigger('click')
    expect(toggles()[1].attributes('aria-expanded')).toBe('true')
    expect(w.find('.pd-expanded-row .details').text()).toBe('1')
    await toggles()[1].trigger('click')
    expect(w.find('.details').exists()).toBe(false)
  })
})
