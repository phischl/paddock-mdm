<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import TimeCell from '../components/TimeCell.vue'
import PackageHoldForm from '../components/PackageHoldForm.vue'
import type { PackageHold } from '../api/client'
import { groupFilter } from '../lib/devices'
import type { ListColumn } from '../lib/listQuery'
import { useManagedPage } from '../lib/managedPage'
import { useProblemText } from '../lib/problems'
import { deletePackageHold, listPackageHolds, savePackageHold, type HoldInput } from '../lib/updates'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/** Package holds (plan M5b decision 2): held packages are left out of every update and refused by install now. */
const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const page = useManagedPage<PackageHold, HoldInput>({
  save: savePackageHold, remove: deletePackageHold, label: (h) => h.package,
  messages: { deleteTitle: 'updates.holds.deleteTitle', deleteConfirm: 'updates.holds.deleteConfirm' },
  reload: () => void list.value?.reload(),
})
const { groups, open, target, problem, pageProblem, openDialog, submit, remove, groupName } = page

const filters = computed(() => [{ ...groupFilter(groups.value), label: 'managed.scope' }])
const columns = computed<ListColumn[]>(() => [
  { key: 'package', title: 'updates.holds.package', sortable: true },
  { key: 'version', title: 'updates.holds.version' },
  { key: 'device_group_id', title: 'managed.scope' },
  { key: 'reason', title: 'updates.holds.reason' },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions' }] : []),
])
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('updates.holds.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        color="primary"
        data-testid="create-hold"
        @click="openDialog(null)"
      >
        {{ t('updates.holds.create') }}
      </v-btn>
    </div>
    <p class="summary">
      {{ t('updates.holds.summary') }}
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
      :fetch="listPackageHolds"
      :filters="filters"
      searchable
      default-sort="package"
      item-value="id"
      empty-icon="package"
      empty-title="updates.holds.empty.title"
      empty-description="updates.holds.empty.description"
      data-testid="hold-list"
    >
      <template #empty-action>
        <v-btn
          v-if="session.canWrite"
          color="primary"
          @click="openDialog(null)"
        >
          {{ t('updates.holds.create') }}
        </v-btn>
      </template>
      <template #[`item.version`]="{ item }: { item: PackageHold }">
        {{ item.version ?? t('updates.holds.installedVersion') }}
      </template>
      <template #[`item.device_group_id`]="{ item }: { item: PackageHold }">
        {{ groupName(item.device_group_id) }}
      </template>
      <template #[`item.reason`]="{ item }: { item: PackageHold }">
        {{ item.reason || '–' }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: PackageHold }">
        <TimeCell :iso="item.updated_at" />
      </template>
      <template #[`item.created_at`]="{ item }: { item: PackageHold }">
        <TimeCell :iso="item.created_at" />
      </template>
      <template #[`item.actions`]="{ item }: { item: PackageHold }">
        <div class="row-actions">
          <v-btn
            :aria-label="t('managed.editLabel', { name: item.package })"
            variant="tonal"
            size="small"
            @click="openDialog(item)"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            :aria-label="t('managed.deleteLabel', { name: item.package })"
            color="error"
            size="small"
            :loading="pending"
            :disabled="pending"
            @click="run(() => remove(item))"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </template>
    </DataList>

    <v-dialog
      v-model="open"
      max-width="44rem"
      :aria-label="target ? t('updates.holds.editTitle') : t('updates.holds.createTitle')"
    >
      <v-card :title="target ? t('updates.holds.editTitle') : t('updates.holds.createTitle')">
        <v-card-text>
          <PackageHoldForm
            :key="target?.id ?? 'new'"
            :groups="groups"
            :initial="target"
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
