<script setup lang="ts">
import { computed, inject } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { DeviceBundle, DeviceResourceStatus, ResourceState } from '../api/client'
import { isReportOnly, listDeviceBundles, listDeviceConfigStatus, resourceStateFilter, resourceStateView } from '../lib/configStatus'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import type { ListColumn } from '../lib/listQuery'

/** The Apply status tab of a device (plan M11 decision 15): what applied, failed or is pending, and its versions. */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceApplyStatus outside the device frame')
const { t } = useI18n()
const route = useRoute()
const id = computed(() => String(route.params.id))
const fetchStatus = computed(() => listDeviceConfigStatus(id.value))
const fetchBundles = computed(() => listDeviceBundles(id.value))
const counts = computed(() => page.device.value?.config_status)
const reportOnly = computed(() => !!page.device.value && isReportOnly(page.device.value))
const states: ResourceState[] = ['applied', 'failed', 'pending', 'drift_corrected']

const statusColumns: ListColumn[] = [
  { key: 'resource_id', title: 'configStatus.resource', sortable: true },
  { key: 'type', title: 'configStatus.type' },
  { key: 'status', title: 'configStatus.status', sortable: true },
  { key: 'message', title: 'configStatus.message' },
  { key: 'bundle_version', title: 'configStatus.version' },
  { key: 'occurred_at', title: 'configStatus.time', sortable: true },
]
const bundleColumns: ListColumn[] = [
  { key: 'version', title: 'configStatus.version', sortable: true },
  { key: 'created_at', title: 'configStatus.compiled', sortable: true },
  { key: 'outcome', title: 'configStatus.outcome' },
  { key: 'mode', title: 'configStatus.mode' },
  { key: 'changed', title: 'configStatus.changed' },
  { key: 'error_count', title: 'configStatus.errors' },
  { key: 'reported_at', title: 'configStatus.reportedAt' },
  { key: 'rollout', title: 'configStatus.rollout' },
]

function outcomeView(b: DeviceBundle): { status: 'ok' | 'critical' | 'neutral'; label: string } {
  if (!b.report) return { status: 'neutral', label: 'configStatus.outcomes.none' }
  return b.report.outcome === 'applied'
    ? { status: 'ok', label: 'configStatus.outcomes.applied' }
    : { status: 'critical', label: 'configStatus.outcomes.rejected' }
}
</script>

<template>
  <div class="pd-device-tab">
    <v-alert
      v-if="reportOnly"
      type="info"
      variant="tonal"
      data-testid="apply-report-only"
    >
      {{ t('configStatus.reportOnly') }}
    </v-alert>
    <p
      v-if="counts"
      class="summary"
      data-testid="apply-counts"
    >
      <template
        v-for="(s, i) in states"
        :key="s"
      >
        <span v-if="i > 0"> · </span>{{ t('configStatus.count.' + s, { count: counts[s] }) }}
      </template>
    </p>
    <DataList
      :columns="statusColumns"
      :fetch="fetchStatus"
      :filters="[resourceStateFilter]"
      searchable
      expandable
      default-sort="resource_id"
      item-value="resource_id"
      empty-icon="file-check"
      empty-title="configStatus.empty.device.title"
      empty-description="configStatus.empty.device.description"
      data-testid="apply-status-list"
    >
      <template #[`item.status`]="{ item }: { item: DeviceResourceStatus }">
        <StatusChip
          :status="resourceStateView(item.status).status"
          :label="t(resourceStateView(item.status).label)"
        />
      </template>
      <template #[`item.message`]="{ item }: { item: DeviceResourceStatus }">
        {{ item.message }}
      </template>
      <template #[`item.occurred_at`]="{ item }: { item: DeviceResourceStatus }">
        <TimeCell :iso="item.occurred_at" />
      </template>
      <template #expanded="{ item }: { item: DeviceResourceStatus }">
        <template v-if="item.changes.length">
          <p>{{ t('configStatus.changes') }}</p>
          <code
            v-for="c in item.changes"
            :key="c"
            class="command"
          >{{ c }}</code>
        </template>
        <p v-else-if="item.message">
          {{ item.message }}
        </p>
        <p v-else>
          {{ t('configStatus.noDetails') }}
        </p>
      </template>
    </DataList>

    <h2>{{ t('configStatus.bundles') }}</h2>
    <DataList
      :columns="bundleColumns"
      :fetch="fetchBundles"
      searchable
      default-sort="-version"
      item-value="version"
      query-prefix="b"
      empty-icon="package"
      empty-title="configStatus.empty.bundles.title"
      empty-description="configStatus.empty.bundles.description"
      data-testid="bundle-history-list"
    >
      <template #[`item.created_at`]="{ item }: { item: DeviceBundle }">
        <TimeCell :iso="item.created_at" />
      </template>
      <template #[`item.outcome`]="{ item }: { item: DeviceBundle }">
        <StatusChip
          :status="outcomeView(item).status"
          :label="t(outcomeView(item).label)"
          :title="item.report?.reason ?? undefined"
        />
      </template>
      <template #[`item.mode`]="{ item }: { item: DeviceBundle }">
        <template v-if="item.report">
          {{ t('configStatus.modes.' + item.report.mode) }}
        </template>
      </template>
      <template #[`item.changed`]="{ item }: { item: DeviceBundle }">
        {{ item.report?.changed }}
      </template>
      <template #[`item.error_count`]="{ item }: { item: DeviceBundle }">
        {{ item.report?.error_count }}
      </template>
      <template #[`item.reported_at`]="{ item }: { item: DeviceBundle }">
        <TimeCell
          v-if="item.report"
          :iso="item.report.occurred_at"
        />
      </template>
      <template #[`item.rollout`]="{ item }: { item: DeviceBundle }">
        {{ item.config_rollout_id }}
      </template>
    </DataList>
  </div>
</template>
