<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { AttentionDevice } from '../api/client'
import AttentionChips from '../components/AttentionChips.vue'
import DataList from '../components/DataList.vue'
import TimeCell from '../components/TimeCell.vue'
import type { ListColumn } from '../lib/listQuery'
import { attentionFilter, listAttentionDevices } from '../lib/updates'

/**
 * Devices that need an administrator (plan M7c decision 33), one row per device with its open conditions, most
 * severe first. The actions — retire, lock, release the quarantine — are on the device page the row links to.
 */
const { t } = useI18n()
const columns: ListColumn[] = [
  { key: 'hostname', title: 'attention.device', sortable: true, role: 'primary' },
  { key: 'severity', title: 'attention.conditions', sortable: true, role: 'status' },
  { key: 'last_contact_at', title: 'devices.lastContact', role: 'meta', hideBelow: 'sm' },
  { key: 'actions', title: 'common.actions', role: 'actions' },
]
</script>

<template>
  <section class="page">
    <h1>{{ t('attention.title') }}</h1>
    <p class="summary">
      {{ t('attention.summary') }}
    </p>
    <DataList
      :columns="columns"
      :fetch="listAttentionDevices"
      :filters="[attentionFilter]"
      searchable
      default-sort="-severity"
      item-value="device_id"
      empty-icon="circle-check"
      empty-title="attention.empty.title"
      empty-description="attention.empty.description"
      data-testid="attention-list"
    >
      <template #[`item.hostname`]="{ item }: { item: AttentionDevice }">
        <RouterLink
          :to="{ name: 'device', params: { id: item.device_id } }"
          class="mono pd-truncate"
          :title="item.hostname"
        >
          {{ item.hostname }}
        </RouterLink>
        <span
          v-if="item.os_release.VERSION_ID"
          class="pd-type-caption pd-muted pd-block"
        >{{ t('overview.attention.os', { release: item.os_release.VERSION_ID }) }}</span>
      </template>
      <template #[`item.severity`]="{ item }: { item: AttentionDevice }">
        <AttentionChips :conditions="item.conditions" />
      </template>
      <template #[`item.last_contact_at`]="{ item }: { item: AttentionDevice }">
        <TimeCell
          v-if="item.last_contact_at"
          :iso="item.last_contact_at"
          mode="relative"
        />
        <span
          v-else
          class="pd-muted"
        >{{ t('time.never') }}</span>
      </template>
      <template #[`item.actions`]="{ item }: { item: AttentionDevice }">
        <v-btn
          :to="{ name: 'device', params: { id: item.device_id } }"
          :aria-label="t('attention.open', { action: t('attention.action.' + item.conditions[0].kind), hostname: item.hostname })"
          size="small"
        >
          {{ t('attention.action.' + item.conditions[0].kind) }}
        </v-btn>
      </template>
    </DataList>
  </section>
</template>
