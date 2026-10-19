<script setup lang="ts">
import { computed, inject, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceLoginEvent } from '../api/client'
import DataList from '../components/DataList.vue'
import TimeCell from '../components/TimeCell.vue'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import type { ListColumn } from '../lib/listQuery'
import { listDeviceLogins, loginHistoryEnabled } from '../lib/loginHistory'
import { useSessionStore } from '../stores/session'

/**
 * The Logins tab of a device (plan M8d decision 20): every session start of a directory user while the organization
 * records its login history. While it is off the tab says so and links administrators to the setting.
 */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceLogins outside the device frame')
const { t } = useI18n()
const session = useSessionStore()
const enabled = ref<boolean | null>(null)
const fetch = computed(() => listDeviceLogins(page.device.value!.id))
const columns: ListColumn[] = [
  { key: 'username', title: 'devices.logins.user', sortable: true, role: 'primary' },
  { key: 'at', title: 'devices.logins.at', sortable: true, role: 'meta' },
]
onMounted(async () => {
  enabled.value = await loginHistoryEnabled()
})
</script>

<template>
  <div class="pd-device-tab">
    <v-alert
      v-if="enabled === false"
      type="info"
      variant="tonal"
      data-testid="device-logins-off"
    >
      {{ t('devices.logins.off') }}
      <RouterLink
        v-if="session.canDelete"
        :to="{ name: 'login-settings' }"
      >
        {{ t('devices.logins.offLink') }}
      </RouterLink>
    </v-alert>
    <DataList
      v-else-if="enabled"
      :columns="columns"
      :fetch="fetch"
      searchable
      default-sort="-at"
      item-value="id"
      empty-icon="inbox"
      empty-title="devices.logins.empty"
      data-testid="device-login-list"
    >
      <template #[`item.at`]="{ item }: { item: DeviceLoginEvent }">
        <TimeCell :iso="item.at" />
      </template>
    </DataList>
  </div>
</template>
