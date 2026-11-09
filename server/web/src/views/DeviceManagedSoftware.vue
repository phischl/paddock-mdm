<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import type { CompileWarning, DeviceManagedSoftware } from '../api/client'
import DataList from '../components/DataList.vue'
import SoftwareStateChip from '../components/SoftwareStateChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { ListColumn } from '../lib/listQuery'
import {
  compileWarningCodeFilter, compileWarningMessage, listCompileWarnings, listDeviceManagedSoftware, softwareIntentFilter, softwareScopeFilter,
  softwareStateFilter, type ScopedRow,
} from '../lib/software'

/**
 * The Managed software tab of a device (plan M13a decision 30): what the catalog manages there and what the device
 * reported, once per scope (plan M13b decision 17), and what the compiler left out of the device's bundle against an
 * assignment (architect decision A10-10).
 */
const { t } = useI18n()
const route = useRoute()
const truncated = ref(false)
const id = computed(() => String(route.params.id))
const fetch = computed(() => listDeviceManagedSoftware(id.value, (v) => (truncated.value = v)))
const fetchWarnings = computed(() => listCompileWarnings({ deviceID: id.value }))
const columns: ListColumn[] = [
  { key: 'name', title: 'software.catalog.name', sortable: true, role: 'primary' },
  { key: 'state', title: 'software.state.label', sortable: true, role: 'status' },
  { key: 'scope', title: 'software.scope.label', role: 'meta' },
  { key: 'intent', title: 'software.assignments.intent', role: 'meta' },
  { key: 'package', title: 'software.catalog.package', role: 'meta', mono: true },
  { key: 'version', title: 'software.assignments.version', role: 'meta', mono: true },
  { key: 'reported_at', title: 'software.reportedAt', sortable: true, role: 'meta' },
]
const warningColumns: ListColumn[] = [
  { key: 'code', title: 'software.compileWarnings.warning', sortable: true, role: 'primary' },
  { key: 'entry', title: 'software.compileWarnings.entry', role: 'meta' },
  { key: 'created_at', title: 'software.compileWarnings.compiledAt', sortable: true, role: 'meta' },
]

function warningText(w: CompileWarning): string {
  const m = compileWarningMessage(w)
  return t(m.key, m.args)
}
</script>

<template>
  <div class="pd-device-tab">
    <p class="summary">
      {{ t('software.device.summary') }}
    </p>
    <v-alert
      v-if="truncated"
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="managed-software-truncated"
    >
      {{ t('software.device.truncated') }}
    </v-alert>
    <DataList
      :columns="columns"
      :fetch="fetch"
      :filters="[softwareStateFilter, softwareIntentFilter, softwareScopeFilter]"
      searchable
      default-sort="name"
      item-value="row_key"
      empty-icon="package"
      empty-title="software.device.empty.title"
      empty-description="software.device.empty.description"
      data-testid="managed-software-list"
    >
      <template #[`item.name`]="{ item }: { item: ScopedRow<DeviceManagedSoftware> }">
        <RouterLink :to="{ name: 'software-catalog-entry', params: { id: item.catalog_entry_id } }">
          {{ item.name }}
        </RouterLink>
      </template>
      <template #[`item.state`]="{ item }: { item: ScopedRow<DeviceManagedSoftware> }">
        <SoftwareStateChip
          :state="item.state"
          :reason="item.reason"
          :error="item.error"
        />
      </template>
      <template #[`item.scope`]="{ item }: { item: ScopedRow<DeviceManagedSoftware> }">
        {{ t('software.scope.' + item.scope) }}
      </template>
      <template #[`item.intent`]="{ item }: { item: ScopedRow<DeviceManagedSoftware> }">
        {{ t('software.intent.' + item.intent) }}
      </template>
      <template #[`item.package`]="{ item }: { item: ScopedRow<DeviceManagedSoftware> }">
        {{ item.package || '–' }}
      </template>
      <template #[`item.version`]="{ item }: { item: ScopedRow<DeviceManagedSoftware> }">
        {{ item.version || '–' }}
      </template>
      <template #[`item.reported_at`]="{ item }: { item: ScopedRow<DeviceManagedSoftware> }">
        <TimeCell
          v-if="item.reported_at"
          :iso="item.reported_at"
          mode="relative"
        />
        <span
          v-else
          class="pd-muted"
        >–</span>
      </template>
    </DataList>

    <h2>{{ t('software.compileWarnings.title') }}</h2>
    <p class="summary">
      {{ t('software.compileWarnings.summary') }}
    </p>
    <DataList
      query-prefix="w"
      :columns="warningColumns"
      :fetch="fetchWarnings"
      :filters="[compileWarningCodeFilter]"
      searchable
      default-sort="-created_at"
      item-value="id"
      empty-icon="package"
      empty-title="software.compileWarnings.empty.title"
      empty-description="software.compileWarnings.empty.description"
      data-testid="device-compile-warning-list"
    >
      <template #[`item.code`]="{ item }: { item: CompileWarning }">
        {{ warningText(item) }}
      </template>
      <template #[`item.entry`]="{ item }: { item: CompileWarning }">
        <RouterLink
          v-if="item.catalog_entry_id"
          :to="{ name: 'software-catalog-entry', params: { id: item.catalog_entry_id } }"
        >
          {{ t('software.compileWarnings.openEntry') }}
        </RouterLink>
        <span
          v-else
          class="pd-muted"
        >–</span>
      </template>
      <template #[`item.created_at`]="{ item }: { item: CompileWarning }">
        <TimeCell
          :iso="item.created_at"
          mode="relative"
        />
      </template>
    </DataList>
  </div>
</template>
