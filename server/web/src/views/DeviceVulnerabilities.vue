<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import CvssScore from '../components/CvssScore.vue'
import DataList from '../components/DataList.vue'
import SeverityChip from '../components/SeverityChip.vue'
import type { VulnerabilityFinding } from '../api/client'
import { formatDateTime } from '../lib/format'
import { listDeviceVulnerabilities, severityFilter } from '../lib/inventory'
import type { ListColumn } from '../lib/listQuery'

const { t, locale } = useI18n()
const route = useRoute()
const id = computed(() => String(route.params.id))
const fetch = computed(() => listDeviceVulnerabilities(id.value))
const columns: ListColumn[] = [
  { key: 'cve', title: 'inventory.cve', sortable: true },
  { key: 'severity', title: 'inventory.severity', sortable: true },
  { key: 'cvss_score', title: 'inventory.cvss', sortable: true },
  { key: 'package', title: 'inventory.package' },
  { key: 'fixed_version', title: 'inventory.fixedVersion' },
  { key: 'first_seen_at', title: 'inventory.firstSeen' },
]
</script>

<template>
  <div class="pd-device-tab">
    <p class="summary">
      {{ t('inventory.severityHint') }}
    </p>
    <DataList
      :columns="columns"
      :fetch="fetch"
      :filters="[severityFilter]"
      searchable
      default-sort="-cve"
      item-value="key"
      data-testid="device-vulnerability-list"
    >
      <template #[`item.cve`]="{ item }: { item: VulnerabilityFinding }">
        <RouterLink :to="{ name: 'vulnerability', params: { cve: item.cve } }">
          {{ item.cve }}
        </RouterLink>
      </template>
      <template #[`item.severity`]="{ item }: { item: VulnerabilityFinding }">
        <SeverityChip :severity="item.severity" />
      </template>
      <template #[`item.cvss_score`]="{ item }: { item: VulnerabilityFinding }">
        <CvssScore
          :score="item.cvss_score"
          :vector="item.cvss_vector"
        />
      </template>
      <template #[`item.package`]="{ item }: { item: VulnerabilityFinding }">
        {{ t('inventory.packageVersion', { name: item.software_name, version: item.software_version }) }}
      </template>
      <template #[`item.fixed_version`]="{ item }: { item: VulnerabilityFinding }">
        {{ item.fixed_version ?? '–' }}
      </template>
      <template #[`item.first_seen_at`]="{ item }: { item: VulnerabilityFinding }">
        {{ formatDateTime(item.first_seen_at, locale) }}
      </template>
    </DataList>
  </div>
</template>
