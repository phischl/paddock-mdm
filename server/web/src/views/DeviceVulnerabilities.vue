<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import CvssScore from '../components/CvssScore.vue'
import DataList from '../components/DataList.vue'
import DeviceTabs from '../components/DeviceTabs.vue'
import SeverityChip from '../components/SeverityChip.vue'
import type { VulnerabilityFinding } from '../api/client'
import { getDevice } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import { listDeviceVulnerabilities, severityFilter } from '../lib/inventory'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'

const { t, locale } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const id = computed(() => String(route.params.id))
const hostname = ref('')
const problem = ref('')
onMounted(async () => {
  const d = await getDevice(id.value)
  if (typeof d === 'string') problem.value = d
  else hostname.value = d.hostname
})
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
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'devices' }">
        {{ t('devices.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-else>
      <h1>{{ hostname }}</h1>
      <DeviceTabs :device-id="id" />
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
    </template>
  </section>
</template>
