<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { AgentRelease } from '../api/client'
import { agentReleaseFilters, listAgentReleases } from '../lib/agentReleases'
import type { ListColumn } from '../lib/listQuery'
import { releaseStatus, rolloutStatus } from '../lib/status'

const { t } = useI18n()

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
      empty-icon="rocket"
      empty-title="agentReleases.empty.title"
      empty-description="agentReleases.empty.description"
      data-testid="agent-release-list"
    >
      <template #[`item.version`]="{ item }: { item: AgentRelease }">
        <RouterLink :to="{ name: 'agent-release', params: { version: item.version } }">
          {{ item.version }}
        </RouterLink>
      </template>
      <template #[`item.status`]="{ item }: { item: AgentRelease }">
        <StatusChip
          :status="releaseStatus(item.status).status"
          :label="t(releaseStatus(item.status).label)"
        />
      </template>
      <template #[`item.rollout_status`]="{ item }: { item: AgentRelease }">
        <StatusChip
          v-if="item.rollout_status"
          :status="rolloutStatus(item.rollout_status).status"
          :label="t(rolloutStatus(item.rollout_status).label)"
        />
        <span
          v-else
          class="pd-muted"
        >{{ t('agentReleases.noRollout') }}</span>
      </template>
      <template #[`item.created_at`]="{ item }: { item: AgentRelease }">
        <TimeCell :iso="item.created_at" />
      </template>
    </DataList>
  </section>
</template>
