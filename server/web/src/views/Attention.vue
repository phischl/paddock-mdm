<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import type { Attention } from '../api/client'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { attentionFilter, listAttention } from '../lib/updates'

/**
 * Devices that need an administrator (plan M5b decision 11), one row per open condition. The actions — retire, lock,
 * release the quarantine — are on the device page the row links to.
 */
const { t, locale } = useI18n()
const columns: ListColumn[] = [
  { key: 'kind', title: 'attention.kind', sortable: true },
  { key: 'hostname', title: 'devices.hostname', sortable: true },
  { key: 'since', title: 'attention.since', sortable: true },
  { key: 'detail', title: 'attention.detail' },
  { key: 'actions', title: 'common.actions' },
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
      :fetch="listAttention"
      :filters="[attentionFilter]"
      searchable
      default-sort="-since"
      item-value="key"
      data-testid="attention-list"
    >
      <template #[`item.kind`]="{ item }: { item: Attention }">
        {{ t('attention.kinds.' + item.kind) }}
      </template>
      <template #[`item.hostname`]="{ item }: { item: Attention }">
        <RouterLink :to="{ name: 'device', params: { id: item.device_id } }">
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.since`]="{ item }: { item: Attention }">
        {{ formatDateTime(item.since, locale) }}
      </template>
      <template #[`item.detail`]="{ item }: { item: Attention }">
        {{ item.detail || '–' }}
      </template>
      <template #[`item.actions`]="{ item }: { item: Attention }">
        <v-btn
          :to="{ name: 'device', params: { id: item.device_id } }"
          :aria-label="t('attention.open', { hostname: item.hostname })"
          variant="tonal"
          size="small"
        >
          {{ t('attention.action.' + item.kind) }}
        </v-btn>
      </template>
    </DataList>
  </section>
</template>
