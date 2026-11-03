<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import type { DeviceManagedSoftware } from '../api/client'
import DataList from '../components/DataList.vue'
import SoftwareStateChip from '../components/SoftwareStateChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { ListColumn } from '../lib/listQuery'
import { listDeviceManagedSoftware, softwareIntentFilter, softwareStateFilter } from '../lib/software'

/** The Managed software tab of a device (plan M13a decision 30): what the catalog manages there and what the device reported. */
const { t } = useI18n()
const route = useRoute()
const truncated = ref(false)
const id = computed(() => String(route.params.id))
const fetch = computed(() => listDeviceManagedSoftware(id.value, (v) => (truncated.value = v)))
const columns: ListColumn[] = [
  { key: 'name', title: 'software.catalog.name', sortable: true, role: 'primary' },
  { key: 'state', title: 'software.state.label', sortable: true, role: 'status' },
  { key: 'intent', title: 'software.assignments.intent', role: 'meta' },
  { key: 'package', title: 'software.catalog.package', role: 'meta', mono: true },
  { key: 'version', title: 'software.assignments.version', role: 'meta', mono: true },
  { key: 'reported_at', title: 'software.reportedAt', sortable: true, role: 'meta' },
]
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
      :filters="[softwareStateFilter, softwareIntentFilter]"
      searchable
      default-sort="name"
      item-value="catalog_entry_id"
      empty-icon="package"
      empty-title="software.device.empty.title"
      empty-description="software.device.empty.description"
      data-testid="managed-software-list"
    >
      <template #[`item.name`]="{ item }: { item: DeviceManagedSoftware }">
        <RouterLink :to="{ name: 'software-catalog-entry', params: { id: item.catalog_entry_id } }">
          {{ item.name }}
        </RouterLink>
      </template>
      <template #[`item.state`]="{ item }: { item: DeviceManagedSoftware }">
        <SoftwareStateChip
          :state="item.state"
          :reason="item.reason"
          :error="item.error"
        />
      </template>
      <template #[`item.intent`]="{ item }: { item: DeviceManagedSoftware }">
        {{ t('software.intent.' + item.intent) }}
      </template>
      <template #[`item.package`]="{ item }: { item: DeviceManagedSoftware }">
        {{ item.package || '–' }}
      </template>
      <template #[`item.version`]="{ item }: { item: DeviceManagedSoftware }">
        {{ item.version || '–' }}
      </template>
      <template #[`item.reported_at`]="{ item }: { item: DeviceManagedSoftware }">
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
  </div>
</template>
