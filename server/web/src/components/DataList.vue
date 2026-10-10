<script setup lang="ts" generic="T">
import { computed, getCurrentInstance, onBeforeUnmount, onMounted, ref, shallowRef, useSlots, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useDisplay } from 'vuetify'
import {
  filterKeys, fromRouteQuery, ListError, maxListDepth, mergeQuery, pageSizes, sanitizeFilters, searchText, toRouteQuery, unprefixQuery,
  type ListColumn, type ListFilter, type ListParams, type Page, type PageSize,
} from '../lib/listQuery'
import type { IconName } from '../lib/icons.gen'
import { reducedMotion } from '../lib/pageContext'
import { useProblemText } from '../lib/problems'
import { mobileBreakpoint } from '../plugins/vuetify'
import EmptyState from './EmptyState.vue'

/**
 * The list of every portal page (ADR 0018, plan M7c decision 21): search, filters, sortable columns, page numbers
 * and items per page, backed by the admin API list contract. The state lives in the route query (prefixed with
 * queryPrefix when two lists share a page). Cell slots (item.<key>) are passed to the table and the cards; row
 * actions are a column with key "actions" and its cell slot. Below 600 px every row is a card and the filters open
 * in a sheet. j/k move a row cursor, Enter/o open the row.
 */
const props = withDefaults(
  defineProps<{
    columns: ListColumn[]
    fetch: (params: ListParams) => Promise<Page<T>>
    filters?: ListFilter[]
    searchable?: boolean
    defaultSort: string
    itemValue: string
    layout?: 'table' | 'cards'
    queryPrefix?: string
    emptyTitle?: string
    emptyDescription?: string
    emptyIcon?: IconName
    expandable?: boolean
    /** The item value of the row to mark as the one currently shown (aria-current, device pane). */
    currentValue?: string
    pageSize?: PageSize
  }>(),
  { filters: () => [], searchable: false, layout: 'table', queryPrefix: undefined, emptyTitle: undefined, emptyDescription: undefined, emptyIcon: 'inbox', expandable: false, currentValue: undefined, pageSize: 25 },
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
const display = useDisplay()
const ownRoute = route.name
const root = ref<HTMLElement | null>(null)
// Rows are clickable (pointer cursor) only when the page listens to row-click.
const rowClickable = !!getCurrentInstance()?.vnode.props?.onRowClick

const keys = computed(() => filterKeys(props.filters))
const sortKeys = computed(() => props.columns.filter((c) => c.sortable).map((c) => c.key))
const defaults = computed<ListParams>(() => ({
  page: 1,
  page_size: props.pageSize,
  sort: props.defaultSort,
  ...Object.fromEntries(keys.value.map((k) => [k, []])),
}))
const ownKeys = computed(() => ['page', 'page_size', 'sort', 'q', ...keys.value])
const params = computed(() =>
  sanitizeFilters(fromRouteQuery(unprefixQuery(route.query, props.queryPrefix), defaults.value, keys.value, sortKeys.value), props.filters),
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
    cursor.value = -1
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
  void router.replace({ query: mergeQuery(route.query, toRouteQuery(next, defaults.value), ownKeys.value, props.queryPrefix) })
}

/** Resets the search and every filter (the filtered empty state). */
function clearFilters(): void {
  search.value = ''
  update({ q: undefined, ...Object.fromEntries(keys.value.map((k) => [k, []])) })
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

const cellClass = (c: ListColumn) => [
  c.mono ? 'pd-cell-mono' : '',
  c.align === 'end' ? 'text-end' : '',
  c.hideBelow ? 'pd-hide-' + c.hideBelow : '',
  c.role === 'primary' ? 'pd-cell-primary' : '',
]
const headers = computed(() => {
  const out = props.columns.map((c) => ({
    title: t(c.title), key: c.key, sortable: c.sortable === true,
    headerProps: { class: cellClass(c) }, cellProps: { class: cellClass(c) },
  }))
  if (props.expandable) out.push({ title: '', key: 'pd-expand', sortable: false, headerProps: { class: [] }, cellProps: { class: ['pd-cell-expand'] } })
  return out
})
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
const activeFilterCount = computed(() => keys.value.filter((k) => (params.value[k] as string[]).length > 0).length)
const hasCriteria = computed(() => !!params.value.q || activeFilterCount.value > 0)
const range = computed(() => {
  const from = (params.value.page - 1) * params.value.page_size + 1
  const values = { from, to: from + items.value.length - 1, total: total.value }
  return result.value?.total_capped ? t('list.rangeCapped', values) : t('list.range', values)
})
const empty = computed(() => !loading.value && !error.value && result.value !== null && items.value.length === 0)

function optionTitle(o: { value: string; title?: string }): string {
  return o.title && te(o.title) ? t(o.title) : o.value
}
function filterValues(key: string): string[] {
  return params.value[key] as string[]
}
const itemKey = (item: T): string => String((item as Record<string, unknown>)[props.itemValue])
const cell = (item: T, key: string): unknown => (item as Record<string, unknown>)[key]

// Layout: cards when asked for or below 600 px; the filters move into a sheet below 600 px.
const mobile = computed(() => display.width.value < mobileBreakpoint)
const cards = computed(() => props.layout === 'cards' || mobile.value)
const filterSheet = ref(false)
const primaryColumn = computed(() => props.columns.find((c) => c.role === 'primary') ?? props.columns[0])
const statusColumns = computed(() => props.columns.filter((c) => c.role === 'status'))
const metaColumns = computed(() => props.columns.filter((c) => c.role === 'meta' || (!c.role && c !== primaryColumn.value && c.key !== 'actions')))
const actionsColumn = computed(() => props.columns.find((c) => c.role === 'actions' || c.key === 'actions'))

// Expanded rows (audit details): the toggle carries aria-expanded and a label with the row number.
const expanded = ref<string[]>([])
function toggleExpanded(item: T): void {
  const key = itemKey(item)
  expanded.value = expanded.value.includes(key) ? expanded.value.filter((k) => k !== key) : [...expanded.value, key]
}

// Row cursor (plan M7c decision 21): j/k from useShortcuts arrive as a window event; the DataList that contains
// the focus handles it, else the first on the page. Enter/o open the row: row-click when the page listens, else the
// row's first link.
const cursor = ref(-1)
function rowElements(): HTMLElement[] {
  return [...(root.value?.querySelectorAll<HTMLElement>('[data-row-index]') ?? [])]
}
function moveCursor(delta: number): void {
  const rows = rowElements()
  if (rows.length === 0) return
  cursor.value = cursor.value < 0 ? (delta > 0 ? 0 : rows.length - 1) : Math.min(rows.length - 1, Math.max(0, cursor.value + delta))
  rows[cursor.value]?.focus()
}
function openCursor(): void {
  const item = items.value[cursor.value]
  if (!item) return
  if (rowClickable) {
    emit('row-click', item)
    return
  }
  rowElements()[cursor.value]?.querySelector<HTMLElement>('a')?.click()
}
function onListShortcut(e: Event): void {
  const lists = [...document.querySelectorAll<HTMLElement>('.data-list')]
  const active = document.activeElement
  const target = lists.find((l) => active && l.contains(active)) ?? lists[0]
  if (target !== root.value) return
  const action = (e as CustomEvent<'down' | 'up' | 'open'>).detail
  if (action === 'down') moveCursor(1)
  else if (action === 'up') moveCursor(-1)
  else openCursor()
}
onMounted(() => window.addEventListener('paddock:list', onListShortcut))
onBeforeUnmount(() => window.removeEventListener('paddock:list', onListShortcut))
function rowProps({ index, item }: { index: number; item: T }): Record<string, unknown> {
  return {
    tabindex: -1,
    'data-row-index': index,
    'aria-current': props.currentValue !== undefined && itemKey(item) === props.currentValue ? 'true' : undefined,
    class: { 'pd-row-cursor': index === cursor.value, 'pd-row-current': props.currentValue !== undefined && itemKey(item) === props.currentValue },
  }
}
/** A click anywhere in a row sets the cursor (delegated: a per-row handler would make Vuetify style every row as clickable). */
function onRootClick(e: MouseEvent): void {
  const row = (e.target as Element | null)?.closest<HTMLElement>('[data-row-index]')
  if (row && root.value?.contains(row)) cursor.value = Number(row.dataset.rowIndex)
}

defineExpose({ reload: load })
</script>

<template>
  <div
    ref="root"
    class="data-list"
    :class="{ 'data-list--cards': cards }"
    @click="onRootClick"
  >
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
      <v-btn
        v-if="mobile && filters.length > 0"
        prepend-icon="pd:funnel"
        data-testid="list-filters-open"
        @click="filterSheet = true"
      >
        {{ t('list.filtersCount', { count: activeFilterCount }) }}
      </v-btn>
      <template v-else>
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
      </template>
    </div>
    <v-dialog
      v-if="mobile && filters.length > 0"
      v-model="filterSheet"
      fullscreen
      :transition="reducedMotion() ? false : 'dialog-bottom-transition'"
      :aria-label="t('list.filters')"
    >
      <v-card data-testid="list-filter-sheet">
        <v-card-title tag="h2">
          {{ t('list.filters') }}
        </v-card-title>
        <v-card-text class="form">
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
          <div class="form-actions">
            <v-btn
              variant="text"
              @click="clearFilters()"
            >
              {{ t('list.clearFilters') }}
            </v-btn>
            <v-btn
              variant="flat"
              color="primary"
              data-testid="list-filters-apply"
              @click="filterSheet = false"
            >
              {{ t('list.applyFilters') }}
            </v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
    <p
      v-if="error"
      class="form-error"
      role="alert"
    >
      {{ problemText(error) }}
    </p>
    <div
      v-if="cards"
      class="pd-cards-panel table"
      :aria-busy="loading"
    >
      <v-progress-linear
        :active="loading"
        :aria-label="t('list.loading')"
        height="2"
        indeterminate
      />
      <ul
        v-if="items.length > 0"
        class="pd-cards"
      >
        <li
          v-for="(item, index) in items"
          :key="itemKey(item)"
          class="pd-card"
          :class="{ 'pd-card--clickable': rowClickable }"
          v-bind="rowProps({ index, item })"
          @click="rowClickable && emit('row-click', item)"
        >
          <div class="pd-card-line">
            <span
              class="pd-card-primary"
              :class="{ 'pd-cell-mono': primaryColumn?.mono }"
            >
              <slot
                v-if="primaryColumn && slots['item.' + primaryColumn.key]"
                :name="'item.' + primaryColumn.key"
                :item="item"
                :value="cell(item, primaryColumn.key)"
              />
              <template v-else-if="primaryColumn">{{ cell(item, primaryColumn.key) }}</template>
            </span>
            <span
              v-for="c in statusColumns"
              :key="c.key"
              class="pd-card-status"
            >
              <slot
                v-if="slots['item.' + c.key]"
                :name="'item.' + c.key"
                :item="item"
                :value="cell(item, c.key)"
              />
              <template v-else>{{ cell(item, c.key) }}</template>
            </span>
          </div>
          <div
            v-if="metaColumns.length > 0"
            class="pd-card-meta pd-type-caption pd-muted"
          >
            <span
              v-for="c in metaColumns"
              :key="c.key"
              class="pd-card-meta-item"
              :class="{ 'pd-cell-mono': c.mono }"
            >
              <span class="pd-card-meta-label">{{ t(c.title) }}: </span>
              <slot
                v-if="slots['item.' + c.key]"
                :name="'item.' + c.key"
                :item="item"
                :value="cell(item, c.key)"
              />
              <template v-else>{{ cell(item, c.key) }}</template>
            </span>
          </div>
          <div
            v-if="actionsColumn && slots['item.' + actionsColumn.key]"
            class="pd-card-actions"
          >
            <slot
              :name="'item.' + actionsColumn.key"
              :item="item"
              :value="cell(item, actionsColumn.key)"
            />
          </div>
          <template v-if="expandable">
            <v-btn
              variant="text"
              size="small"
              :aria-expanded="expanded.includes(itemKey(item)) ? 'true' : 'false'"
              :aria-label="t('list.toggleDetails', { n: index + 1 })"
              :icon="expanded.includes(itemKey(item)) ? 'pd:chevron-down' : 'pd:chevron-right'"
              class="pd-expand-toggle"
              data-testid="list-expand"
              @click.stop="toggleExpanded(item)"
            />
            <div
              v-if="expanded.includes(itemKey(item))"
              class="pd-expanded"
            >
              <slot
                name="expanded"
                :item="item"
              />
            </div>
          </template>
        </li>
      </ul>
    </div>
    <v-data-table-server
      v-else
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
      :expanded="expanded"
      :row-props="rowProps"
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
        <span v-if="!empty">{{ t('common.empty') }}</span>
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
      <template
        v-if="expandable"
        #[`item.pd-expand`]="{ item, index }"
      >
        <v-btn
          variant="text"
          size="small"
          :aria-expanded="expanded.includes(itemKey(item)) ? 'true' : 'false'"
          :aria-label="t('list.toggleDetails', { n: index + 1 })"
          :icon="expanded.includes(itemKey(item)) ? 'pd:chevron-down' : 'pd:chevron-right'"
          data-testid="list-expand"
          @click.stop="toggleExpanded(item)"
        />
      </template>
      <template
        v-if="expandable"
        #expanded-row="{ item, columns: cols }"
      >
        <tr class="pd-expanded-row">
          <td :colspan="cols.length">
            <div class="pd-expanded">
              <slot
                name="expanded"
                :item="item"
              />
            </div>
          </td>
        </tr>
      </template>
    </v-data-table-server>
    <div
      v-if="empty"
      class="pd-list-empty"
    >
      <template v-if="hasCriteria">
        <p class="pd-list-empty-text">
          {{ t('list.noResults') }}
        </p>
        <v-btn
          prepend-icon="pd:x"
          data-testid="list-clear-filters"
          @click="clearFilters()"
        >
          {{ t('list.clearFilters') }}
        </v-btn>
      </template>
      <EmptyState
        v-else-if="emptyTitle"
        :icon="emptyIcon"
        :title="t(emptyTitle)"
        :description="emptyDescription ? t(emptyDescription) : ''"
      >
        <slot name="empty-action" />
      </EmptyState>
      <p
        v-else
        class="pd-list-empty-text"
      >
        {{ t('common.empty') }}
      </p>
    </div>
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
        :total-visible="mobile ? 3 : 7"
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
