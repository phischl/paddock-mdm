<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import CvssScore from '../components/CvssScore.vue'
import DataList from '../components/DataList.vue'
import SeverityChip from '../components/SeverityChip.vue'
import VulnerabilityTile from '../components/VulnerabilityTile.vue'
import type { Vulnerability } from '../api/client'
import { listVulnerabilities, severityFilter } from '../lib/inventory'
import type { ListColumn } from '../lib/listQuery'

const { t } = useI18n()
const columns: ListColumn[] = [
  { key: 'cve', title: 'inventory.cve', sortable: true },
  { key: 'severity', title: 'inventory.severity', sortable: true },
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
      {{ t('inventory.severityHintOrganization') }}
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
        <CvssScore
          :score="item.cvss_score"
          :vector="item.cvss_vector"
        />
      </template>
      <template #[`item.fixed_version`]="{ item }: { item: Vulnerability }">
        {{ item.fixed_version ?? '–' }}
      </template>
    </DataList>
  </section>
</template>
