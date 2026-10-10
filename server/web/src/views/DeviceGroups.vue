<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import DeviceGroupForm from '../components/DeviceGroupForm.vue'
import type { DeviceGroup } from '../api/client'
import { useDeviceGroupPage } from '../lib/deviceGroupPage'
import { listDeviceGroups } from '../lib/deviceGroups'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const {
  createOpen, createProblem, editTarget, editProblem, pageProblem,
  openCreate, onCreate, openEdit, closeEdit, onEdit, onDelete,
} = useDeviceGroupPage(() => void list.value?.reload())

const columns = computed<ListColumn[]>(() => [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'description', title: 'common.description' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions' }] : []),
])
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('deviceGroups.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        data-testid="create-device-group"
        color="primary"
        @click="openCreate"
      >
        {{ t('deviceGroups.create') }}
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
      :fetch="listDeviceGroups"
      searchable
      default-sort="name"
      item-value="id"
      data-testid="device-group-list"
    >
      <template #[`item.name`]="{ item }: { item: DeviceGroup }">
        <RouterLink :to="{ name: 'device-group', params: { id: item.id } }">
          {{ item.name }}
        </RouterLink>
      </template>
      <template #[`item.created_at`]="{ item }: { item: DeviceGroup }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: DeviceGroup }">
        {{ formatDateTime(item.updated_at, locale) }}
      </template>
      <template #[`item.actions`]="{ item }: { item: DeviceGroup }">
        <div class="row-actions">
          <v-btn
            :aria-label="t('deviceGroups.editLabel', { name: item.name })"
            variant="tonal"
            size="small"
            @click="openEdit(item)"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            v-if="session.canDelete"
            :aria-label="t('deviceGroups.deleteLabel', { name: item.name })"
            color="error"
            size="small"
            @click="onDelete(item)"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </template>
    </DataList>

    <v-dialog
      v-model="createOpen"
      max-width="32rem"
      :aria-label="t('deviceGroups.createTitle')"
    >
      <v-card :title="t('deviceGroups.createTitle')">
        <v-card-text>
          <DeviceGroupForm
            id-prefix="create-group"
            :submit-label="t('common.create')"
            :problem="createProblem"
            @submit="onCreate"
            @cancel="createOpen = false"
          />
        </v-card-text>
      </v-card>
    </v-dialog>

    <v-dialog
      :model-value="editTarget !== null"
      max-width="32rem"
      :aria-label="t('deviceGroups.editTitle')"
      @update:model-value="closeEdit"
    >
      <v-card :title="t('deviceGroups.editTitle')">
        <v-card-text>
          <DeviceGroupForm
            v-if="editTarget"
            :key="editTarget.id"
            id-prefix="edit-group"
            :initial-name="editTarget.name"
            :initial-description="editTarget.description"
            :submit-label="t('common.save')"
            :problem="editProblem"
            @submit="onEdit"
            @cancel="closeEdit"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
