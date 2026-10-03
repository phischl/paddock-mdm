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
  wrapper?.unmount()
  wrapper = null
})

async function mountList(url: string, fetch: (p: ListParams) => Promise<Page<Row>>): Promise<{ router: Router; w: VueWrapper }> {
  const Page = () => h(DataList<Row>, { columns, filters, fetch, searchable: true, defaultSort: 'name', itemValue: 'id' })
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
    const done = navigated(router)
    await input.setValue('la')
    await new Promise((resolve) => setTimeout(resolve, 100))
    await input.setValue('lap')
    const typed = performance.now()
    await new Promise((resolve) => setTimeout(resolve, 150))
    expect(router.currentRoute.value.query).toEqual({ page: '3', page_size: '10' })
    await done
    // A timer never fires early: the search waited 300 ms after the last keystroke, and "la" was never searched.
    expect(performance.now() - typed).toBeGreaterThanOrEqual(299)
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

  it('shows the problem of a failed request', async () => {
    const fetch = vi.fn(() => Promise.reject(new ListError('forbidden')))
    const { w } = await mountList('/list', fetch)
    expect(w.find('p[role="alert"]').text()).toBe('You are not allowed to do this.')
  })
})
