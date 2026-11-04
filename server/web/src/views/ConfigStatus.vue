<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import TimeCell from '../components/TimeCell.vue'
import type { ResourceStatus } from '../api/client'
import { listConfigStatus, resourceStateFilter } from '../lib/configStatus'
import type { ListColumn } from '../lib/listQuery'

const { t } = useI18n()
const columns: ListColumn[] = [
  { key: 'resource_id', title: 'configStatus.resource', sortable: true },
  { key: 'type', title: 'configStatus.type' },
  { key: 'applied', title: 'configStatus.states.applied', sortable: true },
  { key: 'failed', title: 'configStatus.states.failed', sortable: true },
  { key: 'pending', title: 'configStatus.states.pending', sortable: true },
  { key: 'drift_corrected', title: 'configStatus.states.drift_corrected' },
  { key: 'last_failure_at', title: 'configStatus.lastFailure' },
]
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('configStatus.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('configStatus.summary') }}
    </p>
    <DataList
      :columns="columns"
      :fetch="listConfigStatus"
      :filters="[resourceStateFilter]"
      searchable
      default-sort="-failed"
      item-value="resource_id"
      empty-icon="file-check"
      empty-title="configStatus.empty.fleet.title"
      empty-description="configStatus.empty.fleet.description"
      data-testid="config-status-list"
    >
      <template #[`item.failed`]="{ item }: { item: ResourceStatus }">
        <span
          :class="item.failed > 0 ? 'pd-tab-count--critical' : 'pd-muted'"
          data-testid="config-status-failed"
        >{{ item.failed }}</span>
      </template>
      <template #[`item.last_failure_at`]="{ item }: { item: ResourceStatus }">
        <TimeCell
          v-if="item.last_failure_at"
          :iso="item.last_failure_at"
        />
      </template>
    </DataList>
  </section>
</template>
