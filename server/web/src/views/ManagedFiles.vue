<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import ManagedFileForm from '../components/ManagedFileForm.vue'
import type { ManagedFile } from '../api/client'
import { groupFilter } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { deleteManagedFile, listManagedFiles, saveManagedFile, type FileInput } from '../lib/managedConfig'
import { useManagedPage } from '../lib/managedPage'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const page = useManagedPage<ManagedFile, FileInput>({
  save: saveManagedFile, remove: deleteManagedFile, label: (f) => f.path,
  messages: { deleteTitle: 'managed.files.deleteTitle', deleteConfirm: 'managed.files.deleteConfirm' },
  reload: () => void list.value?.reload(),
})
const { groups, open, target, problem, pageProblem, openDialog, submit, remove, groupName } = page

const filters = computed(() => [{ ...groupFilter(groups.value), label: 'managed.scope' }])
const columns = computed<ListColumn[]>(() => [
  { key: 'path', title: 'managed.files.path', sortable: true },
  { key: 'device_group_id', title: 'managed.scope' },
  { key: 'mode', title: 'managed.files.mode' },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions' }] : []),
])
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('managed.files.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        color="primary"
        data-testid="create-managed-file"
        @click="openDialog(null)"
      >
        {{ t('managed.files.create') }}
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
      :fetch="listManagedFiles"
      :filters="filters"
      searchable
      default-sort="path"
      item-value="id"
      data-testid="managed-file-list"
    >
      <template #[`item.device_group_id`]="{ item }: { item: ManagedFile }">
        {{ groupName(item.device_group_id) }}
      </template>
      <template #[`item.mode`]="{ item }: { item: ManagedFile }">
        {{ item.mode }} {{ item.owner }}:{{ item.group }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: ManagedFile }">
        {{ formatDateTime(item.updated_at, locale) }}
      </template>
      <template #[`item.created_at`]="{ item }: { item: ManagedFile }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
      <template #[`item.actions`]="{ item }: { item: ManagedFile }">
        <div class="row-actions">
          <v-btn
            :aria-label="t('managed.editLabel', { name: item.path })"
            variant="tonal"
            size="small"
            @click="openDialog(item)"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            :aria-label="t('managed.deleteLabel', { name: item.path })"
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
      :aria-label="target ? t('managed.files.editTitle') : t('managed.files.createTitle')"
    >
      <v-card :title="target ? t('managed.files.editTitle') : t('managed.files.createTitle')">
        <v-card-text>
          <ManagedFileForm
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
