<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import SeverityChip from '../components/SeverityChip.vue'
import VulnerabilityTile from '../components/VulnerabilityTile.vue'
import type { Vulnerability } from '../api/client'
import { formatScore, listVulnerabilities, severityFilter } from '../lib/inventory'
import type { ListColumn } from '../lib/listQuery'

const { t } = useI18n()
const columns: ListColumn[] = [
  { key: 'cve', title: 'inventory.cve', sortable: true },
  { key: 'severity', title: 'inventory.severity' },
  { key: 'cvss_score', title: 'inventory.cvss', sortable: true },
  { key: 'device_count', title: 'inventory.devices', sortable: true },
  { key: 'fixed_version', title: 'inventory.fixedVersion' },
]
</script>

<template>
  <section class="page">
    <h1>{{ t('inventory.vulnerabilitiesTitle') }}</h1>
    <VulnerabilityTile />
    <p class="summary">
      {{ t('inventory.severityHint') }}
    </p>
    <DataList
      :columns="columns"
      :fetch="listVulnerabilities"
      :filters="[severityFilter]"
      searchable
      default-sort="-cve"
      item-value="cve"
      data-testid="vulnerability-list"
    >
      <template #[`item.cve`]="{ item }: { item: Vulnerability }">
        <RouterLink :to="{ name: 'vulnerability', params: { cve: item.cve } }">
          {{ item.cve }}
        </RouterLink>
      </template>
      <template #[`item.severity`]="{ item }: { item: Vulnerability }">
        <SeverityChip :severity="item.severity" />
      </template>
      <template #[`item.cvss_score`]="{ item }: { item: Vulnerability }">
        {{ formatScore(item.cvss_score) }}
      </template>
      <template #[`item.fixed_version`]="{ item }: { item: Vulnerability }">
        {{ item.fixed_version ?? '–' }}
      </template>
    </DataList>
  </section>
</template>
