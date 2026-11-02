<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { ConfigRollout } from '../api/client'
import { configRolloutFilters, listConfigRollouts, rolloutPercent } from '../lib/configRollouts'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { configRolloutStatus } from '../lib/status'

/** The staged configuration rollouts of the organization (plan M11 decision 36). */
const { t, locale } = useI18n()

const columns = computed<ListColumn[]>(() => [
  { key: 'status', title: 'configRollouts.status', sortable: true },
  { key: 'wave', title: 'configRollouts.wave' },
  { key: 'counts', title: 'configRollouts.counts' },
  { key: 'started_by', title: 'configRollouts.startedBy' },
  { key: 'started_at', title: 'configRollouts.startedAt', sortable: true },
  { key: 'actions', title: 'common.actions' },
])
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('configRollouts.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('configRollouts.summary') }}
      <RouterLink to="/settings/rollout">
        {{ t('configRollouts.settingsLink') }}
      </RouterLink>
    </p>
    <DataList
      :columns="columns"
      :fetch="listConfigRollouts"
      :filters="configRolloutFilters"
      searchable
      default-sort="-started_at"
      item-value="id"
      empty-icon="rocket"
      empty-title="configRollouts.empty.title"
      empty-description="configRollouts.empty.description"
      data-testid="config-rollout-list"
    >
      <template #[`item.status`]="{ item }: { item: ConfigRollout }">
        <StatusChip
          :status="configRolloutStatus(item.status).status"
          :label="t(configRolloutStatus(item.status).label)"
          data-testid="config-rollout-status"
        />
      </template>
      <template #[`item.wave`]="{ item }: { item: ConfigRollout }">
        {{ t('configRollouts.waveShort', { wave: item.current_wave_index + 1, waves: item.waves.length, percent: rolloutPercent(item) }) }}
      </template>
      <template #[`item.counts`]="{ item }: { item: ConfigRollout }">
        {{ t('configRollouts.countFacts', item.counts) }}
      </template>
      <template #[`item.started_at`]="{ item }: { item: ConfigRollout }">
        <TimeCell :iso="item.started_at" />
      </template>
      <template #[`item.actions`]="{ item }: { item: ConfigRollout }">
        <div class="row-actions">
          <v-btn
            size="small"
            variant="tonal"
            :to="{ name: 'config-rollout', params: { id: item.id } }"
            :aria-label="t('configRollouts.openLabel', { at: formatDateTime(item.started_at, locale) })"
            data-testid="config-rollout-open"
          >
            {{ t('configRollouts.open') }}
          </v-btn>
        </div>
      </template>
    </DataList>
  </section>
</template>
