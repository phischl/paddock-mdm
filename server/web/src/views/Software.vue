<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import { hasVulnerabilitiesFilter, listSoftware, type Keyed } from '../lib/inventory'
import type { SoftwareSummary } from '../api/client'
import type { ListColumn } from '../lib/listQuery'

const { t } = useI18n()
const columns: ListColumn[] = [
  { key: 'name', title: 'inventory.package', sortable: true },
  { key: 'version', title: 'inventory.version', sortable: true },
  { key: 'device_count', title: 'inventory.devices', sortable: true },
  { key: 'has_vulnerabilities', title: 'inventory.hasVulnerabilities' },
]
</script>

<template>
  <section class="page">
    <h1>{{ t('inventory.softwareTitle') }}</h1>
    <p class="summary">
      {{ t('inventory.softwareHint') }}
    </p>
    <DataList
      :columns="columns"
      :fetch="listSoftware"
      :filters="[hasVulnerabilitiesFilter]"
      searchable
      default-sort="name"
      item-value="key"
      data-testid="software-list"
    >
      <template #[`item.has_vulnerabilities`]="{ item }: { item: Keyed<SoftwareSummary> }">
        {{ item.has_vulnerabilities ? t('inventory.withVulnerabilities') : t('inventory.withoutVulnerabilities') }}
      </template>
    </DataList>
  </section>
</template>
