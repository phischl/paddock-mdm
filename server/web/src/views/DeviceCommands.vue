<script setup lang="ts">
import { computed, inject, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceCommand } from '../api/client'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import type { ListColumn } from '../lib/listQuery'
import { commandFilters, listCommands } from '../lib/localAdmin'
import { commandStatus } from '../lib/status'

/** The Commands tab of a device (plan M7c decision 29): the commands issued to it, newest first. */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceCommands outside the device frame')
const { t } = useI18n()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const fetch = computed(() => listCommands(page.device.value!.id))
const columns: ListColumn[] = [
  { key: 'type', title: 'commands.type', sortable: true, role: 'primary' },
  { key: 'status', title: 'commands.status', sortable: true, role: 'status' },
  { key: 'issued_at', title: 'commands.issuedAt', sortable: true, role: 'meta' },
  { key: 'expires_at', title: 'commands.expiresAt', sortable: true, role: 'meta', hideBelow: 'sm' },
]
watch(page.refresh, () => list.value?.reload())
</script>

<template>
  <div class="pd-device-tab">
    <DataList
      ref="list"
      :columns="columns"
      :fetch="fetch"
      :filters="commandFilters"
      default-sort="-issued_at"
      item-value="id"
      empty-icon="inbox"
      empty-title="commands.empty.title"
      empty-description="commands.empty.description"
      data-testid="command-list"
    >
      <template #[`item.type`]="{ item }: { item: DeviceCommand }">
        {{ t('commands.types.' + item.type) }}
      </template>
      <template #[`item.status`]="{ item }: { item: DeviceCommand }">
        <StatusChip
          :status="commandStatus(item.status).status"
          :label="t(commandStatus(item.status).label)"
        />
      </template>
      <template #[`item.issued_at`]="{ item }: { item: DeviceCommand }">
        <TimeCell :iso="item.issued_at" />
      </template>
      <template #[`item.expires_at`]="{ item }: { item: DeviceCommand }">
        <TimeCell :iso="item.expires_at" />
      </template>
    </DataList>
  </div>
</template>
