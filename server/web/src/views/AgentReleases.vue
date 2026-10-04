<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import type { AgentRelease } from '../api/client'
import { agentReleaseFilters, listAgentReleases } from '../lib/agentReleases'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'

const { t, locale } = useI18n()

const columns: ListColumn[] = [
  { key: 'version', title: 'agentReleases.version', sortable: true },
  { key: 'status', title: 'agentReleases.status', sortable: true },
  { key: 'rollout_status', title: 'agentReleases.rollout' },
  { key: 'artifact_count', title: 'agentReleases.artifacts' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
]
</script>

<template>
  <section class="page">
    <h1>{{ t('agentReleases.title') }}</h1>
    <p>{{ t('agentReleases.uploadHint') }}</p>
    <DataList
      :columns="columns"
      :fetch="listAgentReleases"
      :filters="agentReleaseFilters"
      searchable
      default-sort="-created_at"
      item-value="version"
      data-testid="agent-release-list"
    >
      <template #[`item.version`]="{ item }: { item: AgentRelease }">
        <RouterLink :to="{ name: 'agent-release', params: { version: item.version } }">
          {{ item.version }}
        </RouterLink>
      </template>
      <template #[`item.status`]="{ item }: { item: AgentRelease }">
        {{ t('agentReleases.statuses.' + item.status) }}
      </template>
      <template #[`item.rollout_status`]="{ item }: { item: AgentRelease }">
        {{ item.rollout_status ? t('agentReleases.rolloutStatuses.' + item.rollout_status) : t('agentReleases.noRollout') }}
      </template>
      <template #[`item.created_at`]="{ item }: { item: AgentRelease }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
    </DataList>
  </section>
</template>
