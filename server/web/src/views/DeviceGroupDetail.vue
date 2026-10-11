<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import InstallNowDialog from '../components/InstallNowDialog.vue'
import { api, problemCode, type Device, type DeviceGroup } from '../api/client'
import { listGroupDevices, stateFilter } from '../lib/devices'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { installNowGroup } from '../lib/updates'
import { useSessionStore } from '../stores/session'
import { deviceStatus } from '../lib/status'

const { t } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const session = useSessionStore()
const id = computed(() => String(route.params.id))
const installOpen = ref(false)
const notice = ref('')

async function install(packages: string[]): Promise<{ problem: string; detail?: string } | null> {
  const res = await installNowGroup(id.value, packages)
  if (typeof res !== 'number') return res
  notice.value = t('updates.installNow.requestedGroup', { count: res })
  return null
}
const group = ref<DeviceGroup | null>(null)
const problem = ref('')
onMounted(async () => {
  const { data, error } = await api.GET('/api/v1/device-groups/{id}', { params: { path: { id: id.value } } })
  group.value = data ?? null
  problem.value = data ? '' : problemCode(error)
})

const fetchMembers = computed(() => listGroupDevices(id.value))
const columns: ListColumn[] = [
  { key: 'hostname', title: 'devices.hostname', sortable: true },
  { key: 'state', title: 'devices.state', sortable: true },
  { key: 'last_contact_at', title: 'devices.lastContact', sortable: true },
  { key: 'enrolled_at', title: 'devices.enrolledAt', sortable: true },
]
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'device-groups' }">
        {{ t('deviceGroups.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="group">
      <div class="page-header">
        <h1>{{ group.name }}</h1>
        <v-btn
          v-if="session.canWrite"
          color="primary"
          data-testid="group-install-now"
          @click="installOpen = true"
        >
          {{ t('updates.installNow.label') }}
        </v-btn>
      </div>
      <p
        v-if="notice"
        role="status"
      >
        {{ notice }}
      </p>
      <p class="summary">
        {{ group.description }}
      </p>
      <h2>{{ t('deviceGroups.members') }}</h2>
      <DataList
        :columns="columns"
        :fetch="fetchMembers"
        :filters="[stateFilter]"
        searchable
        default-sort="hostname"
        item-value="id"
        data-testid="group-device-list"
      >
        <template #[`item.hostname`]="{ item }: { item: Device }">
          <RouterLink :to="{ name: 'device', params: { id: item.id } }">
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
        <template #[`item.enrolled_at`]="{ item }: { item: Device }">
          <TimeCell :iso="item.enrolled_at" />
        </template>
      </DataList>
      <InstallNowDialog
        v-model="installOpen"
        :title="t('updates.installNow.titleGroup', { name: group.name })"
        :install="install"
      />
    </template>
  </section>
</template>
