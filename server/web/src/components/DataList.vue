<script setup lang="ts" generic="T">
import { computed, getCurrentInstance, onBeforeUnmount, ref, shallowRef, useSlots, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import {
  filterKeys, fromRouteQuery, ListError, maxListDepth, pageSizes, sanitizeFilters, searchText, toRouteQuery,
  type ListColumn, type ListFilter, type ListParams, type Page, type PageSize,
} from '../lib/listQuery'
import { useProblemText } from '../lib/problems'

/**
 * The list of every portal page (ADR 0018): search, filters, sortable columns, page numbers and items per page,
 * backed by the admin API list contract. The state lives in the route query. Cell slots (item.<key>) are passed
 * to the table; row actions are a column with key "actions" and its cell slot.
 */
const props = withDefaults(
  defineProps<{
    columns: ListColumn[]
    fetch: (params: ListParams) => Promise<Page<T>>
    filters?: ListFilter[]
    searchable?: boolean
    defaultSort: string
    itemValue: string
  }>(),
  { filters: () => [], searchable: false },
)

const emit = defineEmits<{
  'row-click': [item: T]
}>()

/** Search debounce (ADR 0018). */
const searchDelay = 300

const { t, te } = useI18n()
const problemText = useProblemText()
const route = useRoute()
const router = useRouter()
const slots = useSlots()
const ownRoute = route.name
// Rows are clickable (pointer cursor) only when the page listens to row-click.
const rowClickable = !!getCurrentInstance()?.vnode.props?.onRowClick

const keys = computed(() => filterKeys(props.filters))
const sortKeys = computed(() => props.columns.filter((c) => c.sortable).map((c) => c.key))
const defaults = computed<ListParams>(() => ({
  page: 1,
  page_size: 25,
  sort: props.defaultSort,
  ...Object.fromEntries(keys.value.map((k) => [k, []])),
}))
const params = computed(() =>
  sanitizeFilters(fromRouteQuery(route.query, defaults.value, keys.value, sortKeys.value), props.filters),
)

const result = shallowRef<Page<T> | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
let request = 0

async function load(): Promise<void> {
  const current = ++request
  loading.value = true
  error.value = null
  try {
    const page = await props.fetch(params.value)
    if (current !== request) return
    result.value = page
    // The last page emptied (e.g. after a delete): show the new last page.
    if (page.items.length === 0 && page.page > 1 && page.total > 0) {
      update({ page: Math.ceil(page.total / page.page_size) }, false)
    }
  } catch (e) {
    if (current !== request) return
    result.value = null
    error.value = e instanceof ListError ? e.code : 'internal'
  } finally {
    if (current === request) loading.value = false
  }
}

watch(
  () => JSON.stringify(params.value),
  () => {
    if (route.name === ownRoute) void load()
  },
  { immediate: true },
)

/** Writes a new list state to the URL; every change except paging starts again at page 1. */
function update(patch: Partial<ListParams>, resetPage = true): void {
  const next: ListParams = { ...params.value, ...patch }
  if (resetPage) next.page = 1
  void router.replace({ query: toRouteQuery(next, defaults.value) })
}

const search = ref(params.value.q ?? '')
let searchTimer: ReturnType<typeof setTimeout> | undefined
watch(search, (value) => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    const q = searchText(value)
    if (q !== params.value.q) update({ q })
  }, searchDelay)
})
watch(
  () => params.value.q,
  (q) => {
    if (searchText(search.value) !== q) search.value = q ?? ''
  },
)
onBeforeUnmount(() => clearTimeout(searchTimer))

const headers = computed(() =>
  props.columns.map((c) => ({ title: t(c.title), key: c.key, sortable: c.sortable === true })),
)
const sortBy = computed(() => {
  const s = params.value.sort
  return [{ key: s.replace(/^-/, ''), order: s.startsWith('-') ? ('desc' as const) : ('asc' as const) }]
})
function onSort(value: { key: string; order?: boolean | 'asc' | 'desc' }[]): void {
  const s = value[0]
  update({ sort: s ? (s.order === 'desc' ? '-' : '') + s.key : props.defaultSort })
}

const cellSlots = computed(() => Object.keys(slots).filter((name) => name.startsWith('item.')))
const items = computed(() => result.value?.items ?? [])
const total = computed(() => result.value?.total ?? 0)
const pageCount = computed(() => Math.ceil(total.value / params.value.page_size))
const hasCriteria = computed(() => !!params.value.q || keys.value.some((k) => (params.value[k] as string[]).length > 0))
const range = computed(() => {
  const from = (params.value.page - 1) * params.value.page_size + 1
  const values = { from, to: from + items.value.length - 1, total: total.value }
  return result.value?.total_capped ? t('list.rangeCapped', values) : t('list.range', values)
})

function optionTitle(o: { value: string; title?: string }): string {
  return o.title && te(o.title) ? t(o.title) : o.value
}
function filterValues(key: string): string[] {
  return params.value[key] as string[]
}

defineExpose({ reload: load })
</script>

<template>
  <div class="data-list">
    <div
      v-if="searchable || filters.length > 0"
      class="filters"
    >
      <v-text-field
        v-if="searchable"
        v-model="search"
        :label="t('list.search')"
        type="search"
        clearable
        hide-details
        :maxlength="100"
        data-testid="list-search"
      />
      <template
        v-for="f in filters"
        :key="f.kind === 'enum' ? f.key : f.from"
      >
        <v-select
          v-if="f.kind === 'enum'"
          :model-value="filterValues(f.key)"
          :label="t(f.label)"
          :items="f.options.map((o) => ({ value: o.value, title: optionTitle(o) }))"
          multiple
          clearable
          hide-details
          :data-testid="'list-filter-' + f.key"
          @update:model-value="(v: string[] | null) => update({ [f.key]: v ?? [] })"
        />
        <template v-else>
          <v-text-field
            :model-value="filterValues(f.from)[0] ?? ''"
            :label="t(f.fromLabel)"
            type="date"
            hide-details
            :data-testid="'list-filter-' + f.from"
            @update:model-value="(v: string) => update({ [f.from]: v ? [v] : [] })"
          />
          <v-text-field
            :model-value="filterValues(f.to)[0] ?? ''"
            :label="t(f.toLabel)"
            type="date"
            hide-details
            :data-testid="'list-filter-' + f.to"
            @update:model-value="(v: string) => update({ [f.to]: v ? [v] : [] })"
          />
        </template>
      </template>
    </div>
    <p
      v-if="error"
      class="form-error"
      role="alert"
    >
      {{ problemText(error) }}
    </p>
    <v-data-table-server
      :headers="headers"
      :items="items"
      :items-length="total"
      :item-value="itemValue"
      :page="params.page"
      :items-per-page="params.page_size"
      :sort-by="sortBy"
      must-sort
      :loading="loading"
      :aria-busy="loading"
      hide-default-footer
      class="table"
      @update:sort-by="onSort"
      v-on="rowClickable ? { 'click:row': (_: Event, row: { item: T }) => emit('row-click', row.item) } : {}"
    >
      <template #loader="{ color, isActive }">
        <v-progress-linear
          :active="isActive"
          :color="color"
          :aria-label="t('list.loading')"
          absolute
          height="2"
          indeterminate
        />
      </template>
      <template #no-data>
        {{ t(hasCriteria ? 'list.noResults' : 'common.empty') }}
      </template>
      <template
        v-for="name in cellSlots"
        :key="name"
        #[name]="slotProps"
      >
        <slot
          :name="name"
          v-bind="slotProps"
        />
      </template>
    </v-data-table-server>
    <div class="list-footer">
      <v-select
        :model-value="params.page_size"
        :items="[...pageSizes]"
        :label="t('list.pageSize')"
        density="compact"
        hide-details
        class="page-size"
        data-testid="list-page-size"
        @update:model-value="(v: PageSize) => update({ page_size: v })"
      />
      <span
        class="list-range"
        data-testid="list-range"
      >{{ range }}</span>
      <v-pagination
        v-if="pageCount > 1"
        :model-value="params.page"
        :length="pageCount"
        :total-visible="7"
        density="comfortable"
        data-testid="list-pagination"
        @update:model-value="(p: number) => update({ page: p }, false)"
      />
    </div>
    <p
      v-if="result?.total_capped"
      class="summary"
      role="status"
    >
      {{ t('list.cappedHint', { total: maxListDepth }) }}
    </p>
  </div>
</template>
