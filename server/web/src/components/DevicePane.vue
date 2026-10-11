<script setup lang="ts">
import { computed, inject } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { Device } from '../api/client'
import DataList from './DataList.vue'
import StatusChip from './StatusChip.vue'
import { groupFilter, listDevices, stateFilter } from '../lib/devices'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import type { ListColumn } from '../lib/listQuery'
import { deviceStatus } from '../lib/status'

/**
 * The device list beside an open device (plan M7c decision 29): cards with the hostname and the status chip, its
 * own query keys (pane.*); a click opens the same tab of another device. Hidden below 960 px.
 */
const props = defineProps<{ currentId: string }>()
const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const page = inject(deviceDetailKey)
const filters = computed(() => [stateFilter, groupFilter(page?.groups.value ?? [])])
const columns: ListColumn[] = [
  { key: 'hostname', title: 'devices.hostname', role: 'primary', mono: true },
  { key: 'state', title: 'devices.state', role: 'status' },
]

function open(item: Device): void {
  if (item.id === props.currentId) return
  void router.push({ name: route.name ?? 'device', params: { id: item.id }, query: route.query })
}
</script>

<template>
  <aside
    class="pd-pane"
    data-testid="device-pane"
    aria-labelledby="device-pane-title"
  >
    <h2
      id="device-pane-title"
      class="visually-hidden"
    >
      {{ t('devices.pane') }}
    </h2>
    <DataList
      :columns="columns"
      :fetch="listDevices"
      :filters="filters"
      searchable
      layout="cards"
      query-prefix="pane"
      default-sort="hostname"
      item-value="id"
      :current-value="currentId"
      :page-size="25"
      @row-click="open"
    >
      <template #[`item.hostname`]="{ item }: { item: Device }">
        <RouterLink
          :to="{ name: route.name ?? 'device', params: { id: item.id }, query: route.query }"
          :title="item.hostname"
        >
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.state`]="{ item }: { item: Device }">
        <StatusChip
          :status="deviceStatus(item).status"
          :label="t(deviceStatus(item).label)"
        />
      </template>
    </DataList>
  </aside>
</template>
