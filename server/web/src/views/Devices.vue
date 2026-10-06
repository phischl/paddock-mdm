<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import type { Device } from '../api/client'
import { allGroups, groupFilter, listDevices, stateFilter } from '../lib/devices'
import { diskStateFilter } from '../lib/disk'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'

const { t, locale } = useI18n()
const groups = ref<{ id: string; name: string }[]>([])
onMounted(async () => {
  groups.value = await allGroups()
})

const filters = computed(() => [stateFilter, groupFilter(groups.value), diskStateFilter])
const columns: ListColumn[] = [
  { key: 'hostname', title: 'devices.hostname', sortable: true },
  { key: 'state', title: 'devices.state', sortable: true },
  { key: 'last_contact_at', title: 'devices.lastContact', sortable: true },
  { key: 'bundle_version', title: 'devices.bundleVersion' },
  { key: 'agent_version', title: 'devices.agentVersion' },
  { key: 'disk_state', title: 'devices.disk.state' },
  { key: 'enrolled_at', title: 'devices.enrolledAt', sortable: true },
]
</script>

<template>
  <section class="page">
    <h1>{{ t('devices.title') }}</h1>
    <DataList
      :columns="columns"
      :fetch="listDevices"
      :filters="filters"
      searchable
      default-sort="hostname"
      item-value="id"
      data-testid="device-list"
    >
      <template #[`item.hostname`]="{ item }: { item: Device }">
        <RouterLink :to="{ name: 'device', params: { id: item.id } }">
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.state`]="{ item }: { item: Device }">
        <span :class="'state state-' + item.state">{{ t('devices.states.' + item.state) }}</span>
      </template>
      <template #[`item.last_contact_at`]="{ item }: { item: Device }">
        {{ item.last_contact_at ? formatDateTime(item.last_contact_at, locale) : t('devices.never') }}
      </template>
      <template #[`item.bundle_version`]="{ item }: { item: Device }">
        {{ t('devices.versions', { applied: item.applied_bundle_version ?? 0, latest: item.bundle_version }) }}
      </template>
      <template #[`item.agent_version`]="{ item }: { item: Device }">
        {{ item.agent_version ?? '–' }}
      </template>
      <template #[`item.disk_state`]="{ item }: { item: Device }">
        {{ item.disk_state ? t('devices.disk.states.' + item.disk_state) : '–' }}
      </template>
      <template #[`item.enrolled_at`]="{ item }: { item: Device }">
        {{ formatDateTime(item.enrolled_at, locale) }}
      </template>
    </DataList>
  </section>
</template>
