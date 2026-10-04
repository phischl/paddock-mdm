<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import { api, problemCode, type Device, type DeviceGroup } from '../api/client'
import { listGroupDevices, stateFilter } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'

const { t, locale } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const id = computed(() => String(route.params.id))
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
      <h1>{{ group.name }}</h1>
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
          {{ t('devices.states.' + item.state) }}
        </template>
        <template #[`item.last_contact_at`]="{ item }: { item: Device }">
          {{ item.last_contact_at ? formatDateTime(item.last_contact_at, locale) : t('devices.never') }}
        </template>
        <template #[`item.enrolled_at`]="{ item }: { item: Device }">
          {{ formatDateTime(item.enrolled_at, locale) }}
        </template>
      </DataList>
    </template>
  </section>
</template>
