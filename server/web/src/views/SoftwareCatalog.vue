<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import SoftwareCatalogEntryForm from '../components/SoftwareCatalogEntryForm.vue'
import TimeCell from '../components/TimeCell.vue'
import type { SoftwareCatalogEntry } from '../api/client'
import { usePending } from '../composables/usePending'
import type { ListColumn, ListFilter } from '../lib/listQuery'
import { allSoftwareSources, catalogCategories, listSoftwareCatalog, saveCatalogEntry, type EntryInput } from '../lib/software'
import { useSessionStore } from '../stores/session'

const { t } = useI18n()
const { pending, run } = usePending()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const sources = ref<{ id: string; slug: string; name: string }[]>([])
const categories = ref<string[]>([])
const open = ref(false)
const problem = ref('')
const formKey = ref(0)

const filters = computed<ListFilter[]>(() => [
  { kind: 'enum', key: 'category', label: 'software.catalog.category', options: categories.value.map((value) => ({ value })) },
  { kind: 'enum', key: 'source_id', label: 'software.catalog.source', options: sources.value.map((s) => ({ value: s.id, title: s.name })) },
])
const columns = computed<ListColumn[]>(() => [
  { key: 'name', title: 'software.catalog.name', sortable: true, role: 'primary' },
  { key: 'category', title: 'software.catalog.category', sortable: true, role: 'meta' },
  { key: 'source_slug', title: 'software.catalog.source', role: 'meta' },
  { key: 'packages', title: 'software.catalog.packages', role: 'meta', align: 'end' },
  { key: 'assignment_count', title: 'software.catalog.assignments', role: 'meta', align: 'end' },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true, role: 'meta' },
])

async function loadOptions(): Promise<void> {
  const [s, c] = await Promise.all([allSoftwareSources().catch(() => []), catalogCategories().catch(() => [])])
  sources.value = s
  categories.value = c
}
onMounted(loadOptions)

function openDialog(): void {
  problem.value = ''
  formKey.value++
  open.value = true
}

async function submit(input: EntryInput): Promise<void> {
  problem.value = (await saveCatalogEntry(null, input)) ?? ''
  if (problem.value) return
  open.value = false
  await Promise.all([list.value?.reload(), loadOptions()])
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('software.catalog.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        color="primary"
        data-testid="create-entry"
        @click="openDialog"
      >
        {{ t('software.catalog.create') }}
      </v-btn>
    </div>
    <p class="summary">
      {{ t('software.catalog.summary') }}
    </p>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listSoftwareCatalog"
      :filters="filters"
      searchable
      default-sort="name"
      item-value="id"
      empty-icon="package"
      empty-title="software.catalog.empty.title"
      empty-description="software.catalog.empty.description"
      data-testid="catalog-list"
    >
      <template #[`item.name`]="{ item }: { item: SoftwareCatalogEntry }">
        <RouterLink :to="{ name: 'software-catalog-entry', params: { id: item.id } }">
          {{ item.name }}
        </RouterLink>
      </template>
      <template #[`item.source_slug`]="{ item }: { item: SoftwareCatalogEntry }">
        {{ item.source_slug || t('software.catalog.distributionRepositories') }}
      </template>
      <template #[`item.packages`]="{ item }: { item: SoftwareCatalogEntry }">
        {{ item.packages.length }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: SoftwareCatalogEntry }">
        <TimeCell :iso="item.updated_at" />
      </template>
    </DataList>

    <v-dialog
      v-model="open"
      max-width="56rem"
      :aria-label="t('software.catalog.createTitle')"
    >
      <v-card :title="t('software.catalog.createTitle')">
        <v-card-text>
          <SoftwareCatalogEntryForm
            :key="formKey"
            :sources="sources"
            :problem="problem"
            :pending="pending"
            @submit="run(() => submit($event))"
            @cancel="open = false"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
