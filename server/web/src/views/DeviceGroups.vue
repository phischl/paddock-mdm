<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import DeviceGroupForm from '../components/DeviceGroupForm.vue'
import { useDeviceGroupPage } from '../lib/deviceGroupPage'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const problemText = useProblemText()
const session = useSessionStore()
const {
  groups, createOpen, createProblem, editTarget, editProblem, deleteTarget, deleteProblem,
  openCreate, onCreate, openEdit, closeEdit, onEdit, openDelete, closeDelete, onDelete,
} = useDeviceGroupPage()

const headers = computed(() => [
  { title: t('common.name'), key: 'name', sortable: false },
  { title: t('common.description'), key: 'description', sortable: false },
  { title: t('common.updatedAt'), key: 'updated_at', sortable: false },
  ...(session.canWrite ? [{ title: t('common.actions'), key: 'actions', sortable: false }] : []),
])

onMounted(() => groups.load())
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
    <p class="summary">
      {{ t('deviceGroups.count', { count: groups.items.value.length }) }}
    </p>
    <p
      v-if="groups.error.value"
      class="form-error"
      role="alert"
    >
      {{ problemText(groups.error.value) }}
    </p>
    <v-data-table
      :headers="headers"
      :items="groups.items.value"
      item-value="id"
      :items-per-page="-1"
      :loading="groups.loading.value"
      hide-default-footer
      class="table"
    >
      <template #no-data>
        {{ t('common.empty') }}
      </template>
      <template #[`item.updated_at`]="{ item }">
        {{ formatDateTime(item.updated_at, locale) }}
      </template>
      <template #[`item.actions`]="{ item }">
        <div class="row-actions">
          <v-btn
            :aria-label="t('deviceGroups.editLabel', { name: item.name })"
            variant="tonal"
            size="small"
            @click="openEdit(item.id)"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            v-if="session.canDelete"
            :aria-label="t('deviceGroups.deleteLabel', { name: item.name })"
            color="error"
            size="small"
            @click="openDelete(item.id)"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </template>
    </v-data-table>
    <v-btn
      v-if="groups.hasMore.value"
      variant="tonal"
      @click="groups.load(true)"
    >
      {{ t('common.loadMore') }}
    </v-btn>

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

    <v-dialog
      :model-value="deleteTarget !== null"
      max-width="32rem"
      :aria-label="t('deviceGroups.deleteTitle')"
      @update:model-value="closeDelete"
    >
      <v-card :title="t('deviceGroups.deleteTitle')">
        <v-card-text>
          <p>{{ t('deviceGroups.deleteConfirm', { name: deleteTarget?.name ?? '' }) }}</p>
          <p
            v-if="deleteProblem"
            class="form-error"
            role="alert"
          >
            {{ problemText(deleteProblem) }}
          </p>
          <div class="form-actions">
            <v-btn
              variant="tonal"
              @click="closeDelete"
            >
              {{ t('common.cancel') }}
            </v-btn>
            <v-btn
              color="error"
              @click="onDelete"
            >
              {{ t('common.delete') }}
            </v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
