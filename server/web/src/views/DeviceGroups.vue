<script setup lang="ts">
import { onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
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

onMounted(() => groups.load())
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('deviceGroups.title') }}</h1>
      <Button
        v-if="session.canWrite"
        data-testid="create-device-group"
        :label="t('deviceGroups.create')"
        @click="openCreate"
      />
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
    <DataTable
      :value="groups.items.value"
      data-key="id"
      :loading="groups.loading.value"
      class="table"
    >
      <template #empty>
        {{ t('common.empty') }}
      </template>
      <Column
        field="name"
        :header="t('common.name')"
      />
      <Column
        field="description"
        :header="t('common.description')"
      />
      <Column :header="t('common.updatedAt')">
        <template #body="{ data }">
          {{ formatDateTime(data.updated_at, locale) }}
        </template>
      </Column>
      <Column
        v-if="session.canWrite"
        :header="t('common.actions')"
      >
        <template #body="{ data }">
          <div class="row-actions">
            <Button
              :label="t('common.edit')"
              :aria-label="t('deviceGroups.editLabel', { name: data.name })"
              severity="secondary"
              size="small"
              @click="openEdit(data.id)"
            />
            <Button
              v-if="session.canDelete"
              :label="t('common.delete')"
              :aria-label="t('deviceGroups.deleteLabel', { name: data.name })"
              severity="danger"
              size="small"
              @click="openDelete(data.id)"
            />
          </div>
        </template>
      </Column>
    </DataTable>
    <Button
      v-if="groups.nextCursor.value"
      :label="t('common.loadMore')"
      severity="secondary"
      @click="groups.load(true)"
    />

    <Dialog
      v-model:visible="createOpen"
      modal
      :header="t('deviceGroups.createTitle')"
    >
      <DeviceGroupForm
        id-prefix="create-group"
        :submit-label="t('common.create')"
        :problem="createProblem"
        @submit="onCreate"
        @cancel="createOpen = false"
      />
    </Dialog>

    <Dialog
      :visible="editTarget !== null"
      modal
      :header="t('deviceGroups.editTitle')"
      @update:visible="closeEdit"
    >
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
    </Dialog>

    <Dialog
      :visible="deleteTarget !== null"
      modal
      :header="t('deviceGroups.deleteTitle')"
      @update:visible="closeDelete"
    >
      <p>{{ t('deviceGroups.deleteConfirm', { name: deleteTarget?.name ?? '' }) }}</p>
      <p
        v-if="deleteProblem"
        class="form-error"
        role="alert"
      >
        {{ problemText(deleteProblem) }}
      </p>
      <div class="form-actions">
        <Button
          severity="secondary"
          :label="t('common.cancel')"
          @click="closeDelete"
        />
        <Button
          severity="danger"
          :label="t('common.delete')"
          @click="onDelete"
        />
      </div>
    </Dialog>
  </section>
</template>
