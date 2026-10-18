<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { Device } from '../api/client'
import {
  allGroups, componentFilter, contactFilter, groupFilter, listDevices, ownerFilter, ownerNames, securityFilter, stateFilter,
} from '../lib/devices'
import { paneQuery } from '../lib/deviceHealth'
import { diskStateFilter } from '../lib/disk'
import type { ListColumn } from '../lib/listQuery'
import { deviceStatus, encryptionStatus } from '../lib/status'
import { allUsers } from '../lib/users'
import { useSessionStore } from '../stores/session'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const groups = ref<{ id: string; name: string }[]>([])
const users = ref<{ id: string; username: string }[]>([])
onMounted(async () => {
  const [g, u] = await Promise.all([allGroups(), allUsers()])
  groups.value = g
  users.value = u
})

const filters = computed(() => [
  stateFilter, contactFilter, groupFilter(groups.value), diskStateFilter, securityFilter, ownerFilter(users.value), componentFilter,
])
const columns: ListColumn[] = [
  { key: 'hostname', title: 'devices.hostname', sortable: true },
  { key: 'state', title: 'devices.state', sortable: true, role: 'status' },
  { key: 'last_contact_at', title: 'devices.lastContact', sortable: true },
  { key: 'bundle_version', title: 'devices.bundleVersion' },
  { key: 'agent_version', title: 'devices.agentVersion' },
  { key: 'disk_state', title: 'devices.disk.state', role: 'status' },
  { key: 'owners', title: 'devices.owners.column' },
  { key: 'components', title: 'devices.components.column' },
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
      empty-icon="laptop"
      empty-title="devices.empty.title"
      empty-description="devices.empty.description"
      data-testid="device-list"
    >
      <template #empty-action>
        <v-btn
          v-if="session.canDelete"
          color="primary"
          @click="router.push({ name: 'enrollment-tokens' })"
        >
          {{ t('devices.empty.action') }}
        </v-btn>
      </template>
      <template #[`item.hostname`]="{ item }: { item: Device }">
        <RouterLink :to="{ name: 'device', params: { id: item.id }, query: paneQuery(route.query) }">
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.state`]="{ item }: { item: Device }">
        <StatusChip
          :status="deviceStatus(item).status"
          :label="t(deviceStatus(item).label)"
        />
      </template>
      <template #[`item.last_contact_at`]="{ item }: { item: Device }">
        <TimeCell
          v-if="item.last_contact_at"
          :iso="item.last_contact_at"
          mode="relative"
        />
        <span
          v-else
          class="pd-muted"
        >{{ t('devices.never') }}</span>
      </template>
      <template #[`item.bundle_version`]="{ item }: { item: Device }">
        {{ t('devices.versions', { applied: item.applied_bundle_version ?? 0, latest: item.bundle_version }) }}
      </template>
      <template #[`item.agent_version`]="{ item }: { item: Device }">
        {{ item.agent_version ?? '–' }}
      </template>
      <template #[`item.disk_state`]="{ item }: { item: Device }">
        <StatusChip
          :status="encryptionStatus(item.disk_state).status"
          :label="t(encryptionStatus(item.disk_state).label)"
        />
      </template>
      <template #[`item.owners`]="{ item }: { item: Device }">
        <span :class="item.owners.length === 0 ? 'pd-muted' : ''">{{ ownerNames(item) || '–' }}</span>
      </template>
      <template #[`item.components`]="{ item }: { item: Device }">
        <span
          v-if="item.components_outdated.length > 0"
          data-testid="device-components-outdated"
        >{{ t('devices.components.outdatedCount', { count: item.components_outdated.length }) }}</span>
        <span v-else>{{ t('devices.components.status.ok') }}</span>
      </template>
      <template #[`item.enrolled_at`]="{ item }: { item: Device }">
        <TimeCell :iso="item.enrolled_at" />
      </template>
    </DataList>
  </section>
</template>
