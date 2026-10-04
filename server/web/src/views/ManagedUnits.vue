<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import ManagedUnitForm from '../components/ManagedUnitForm.vue'
import type { ManagedUnit } from '../api/client'
import { groupFilter } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { deleteManagedUnit, listManagedUnits, saveManagedUnit, type UnitInput } from '../lib/managedConfig'
import { useManagedPage } from '../lib/managedPage'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const page = useManagedPage<ManagedUnit, UnitInput>({
  save: saveManagedUnit, remove: deleteManagedUnit, label: (u) => u.unit,
  messages: { deleteTitle: 'managed.units.deleteTitle', deleteConfirm: 'managed.units.deleteConfirm' },
  reload: () => void list.value?.reload(),
})
const { groups, open, target, problem, pageProblem, openDialog, submit, remove, groupName } = page

const filters = computed(() => [{ ...groupFilter(groups.value), label: 'managed.scope' }])
const columns = computed<ListColumn[]>(() => [
  { key: 'unit', title: 'managed.units.unit', sortable: true },
  { key: 'device_group_id', title: 'managed.scope' },
  { key: 'enabled', title: 'managed.units.wanted' },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions' }] : []),
])
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('managed.units.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        color="primary"
        data-testid="create-managed-unit"
        @click="openDialog(null)"
      >
        {{ t('managed.units.create') }}
      </v-btn>
    </div>
    <p
      v-if="pageProblem"
      class="form-error"
      role="alert"
    >
      {{ problemText(pageProblem) }}
    </p>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listManagedUnits"
      :filters="filters"
      searchable
      default-sort="unit"
      item-value="id"
      data-testid="managed-unit-list"
    >
      <template #[`item.device_group_id`]="{ item }: { item: ManagedUnit }">
        {{ groupName(item.device_group_id) }}
      </template>
      <template #[`item.enabled`]="{ item }: { item: ManagedUnit }">
        {{ t('managed.units.wantedState', { enabled: String(item.enabled), active: String(item.active) }) }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: ManagedUnit }">
        {{ formatDateTime(item.updated_at, locale) }}
      </template>
      <template #[`item.created_at`]="{ item }: { item: ManagedUnit }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
      <template #[`item.actions`]="{ item }: { item: ManagedUnit }">
        <div class="row-actions">
          <v-btn
            :aria-label="t('managed.editLabel', { name: item.unit })"
            variant="tonal"
            size="small"
            @click="openDialog(item)"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            :aria-label="t('managed.deleteLabel', { name: item.unit })"
            color="error"
            size="small"
            @click="remove(item)"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </template>
    </DataList>

    <v-dialog
      v-model="open"
      max-width="44rem"
      :aria-label="target ? t('managed.units.editTitle') : t('managed.units.createTitle')"
    >
      <v-card :title="target ? t('managed.units.editTitle') : t('managed.units.createTitle')">
        <v-card-text>
          <ManagedUnitForm
            :key="target?.id ?? 'new'"
            :groups="groups"
            :initial="target"
            :problem="problem"
            @submit="submit"
            @cancel="open = false"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
