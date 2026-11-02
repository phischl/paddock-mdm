<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import ManagedDeleteDialog from '../components/ManagedDeleteDialog.vue'
import ManagedFileForm from '../components/ManagedFileForm.vue'
import type { ManagedFile, ManagedFileTier } from '../api/client'
import { groupFilter } from '../lib/devices'
import type { ListColumn } from '../lib/listQuery'
import { deleteManagedFile, listManagedFiles, saveManagedFile, type FileInput } from '../lib/managedConfig'
import { useManagedPage } from '../lib/managedPage'
import { useProblemText } from '../lib/problems'
import type { Status } from '../lib/status'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const page = useManagedPage<ManagedFile, FileInput>({
  // Files on sensitive paths need a step-up (ADR 0034 decision 2), and so does the urgent opt-out (plan M11 decision 26).
  save: saveManagedFile, remove: deleteManagedFile, label: (f) => f.path, stepUpAction: 'managed-file',
  messages: { deleteTitle: 'managed.files.deleteTitle', deleteConfirm: 'managed.files.deleteConfirm' },
  reload: () => void list.value?.reload(),
})
const {
  groups, open, target, problem, pageProblem, openDialog, submit, remove, groupName, rolloutsEnabled, deleting, deleteMessage, confirmDelete,
} = page

const tierStatus: Record<ManagedFileTier, Status> = { ordinary: 'neutral', sensitive: 'warn', denied: 'critical' }

const filters = computed(() => [{ ...groupFilter(groups.value), label: 'managed.scope' }])
const columns = computed<ListColumn[]>(() => [
  { key: 'path', title: 'managed.files.path', sortable: true },
  { key: 'device_group_id', title: 'managed.scope' },
  { key: 'tier', title: 'managedFiles.tierColumn' },
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
      class="summary"
      data-testid="operator-roots-hint"
    >
      {{ t('managed.files.operatorRootsHint') }}
      <RouterLink to="/settings/managed-files">
        {{ t('managed.files.operatorRootsLink') }}
      </RouterLink>
    </p>
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
      empty-icon="file-text"
      empty-title="managed.files.empty.title"
      empty-description="managed.files.empty.description"
      data-testid="managed-file-list"
    >
      <template #empty-action>
        <v-btn
          v-if="session.canWrite"
          color="primary"
          @click="openDialog(null)"
        >
          {{ t('managed.files.create') }}
        </v-btn>
      </template>
      <template #[`item.device_group_id`]="{ item }: { item: ManagedFile }">
        {{ groupName(item.device_group_id) }}
      </template>
      <template #[`item.tier`]="{ item }: { item: ManagedFile }">
        <StatusChip
          :status="tierStatus[item.tier]"
          :label="t('managedFiles.tier.' + item.tier)"
          data-testid="managed-file-tier"
        />
      </template>
      <template #[`item.mode`]="{ item }: { item: ManagedFile }">
        {{ item.mode }} {{ item.owner }}:{{ item.group }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: ManagedFile }">
        <TimeCell :iso="item.updated_at" />
      </template>
      <template #[`item.created_at`]="{ item }: { item: ManagedFile }">
        <TimeCell :iso="item.created_at" />
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
          <v-alert
            v-if="problem === 'forbidden'"
            type="warning"
            variant="tonal"
            class="conflict"
            data-testid="sensitive-forbidden"
          >
            {{ t('managedFiles.sensitiveForbidden') }}
          </v-alert>
          <ManagedFileForm
            :key="target?.id ?? 'new'"
            :groups="groups"
            :rollouts-enabled="rolloutsEnabled"
            :initial="target"
            :problem="problem"
            :pending="pending"
            @submit="run(() => submit($event))"
            @cancel="open = false"
          />
        </v-card-text>
      </v-card>
    </v-dialog>

    <ManagedDeleteDialog
      v-if="deleting"
      :title="t('managed.files.deleteTitle')"
      :message="deleteMessage"
      :rollouts-enabled="rolloutsEnabled"
      @confirm="confirmDelete"
      @cancel="deleting = null"
    />
  </section>
</template>
