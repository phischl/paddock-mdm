<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { listDeviceSoftware, listDeviceVulnerabilities } from '../lib/inventory'

/**
 * The tabs of a device (plan M7c decision 29): URL-bound, Alt+1…9 through the shell's shortcut event. Software and
 * Vulnerabilities carry their counts, loaded lazily.
 */
const props = defineProps<{ deviceId: string }>()
const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const software = ref<number | null>(null)
const findings = ref<number | null>(null)

interface Tab { name: string; label: string; testid: string }
const tabs = computed<Tab[]>(() => [
  { name: 'device', label: 'devices.tabs.overview', testid: 'tab-overview' },
  { name: 'device-software', label: 'inventory.tabs.software', testid: 'tab-software' },
  { name: 'device-vulnerabilities', label: 'inventory.tabs.vulnerabilities', testid: 'tab-vulnerabilities' },
  { name: 'device-access', label: 'devices.tabs.access', testid: 'tab-access' },
  { name: 'device-configuration', label: 'devices.tabs.configuration', testid: 'tab-configuration' },
  { name: 'device-commands', label: 'devices.tabs.commands', testid: 'tab-commands' },
])

async function loadCounts(): Promise<void> {
  const page = { page: 1, page_size: 10 as const }
  const [s, v] = await Promise.all([
    listDeviceSoftware(props.deviceId)({ ...page, sort: 'name' }).catch(() => null),
    listDeviceVulnerabilities(props.deviceId)({ ...page, sort: '-severity' }).catch(() => null),
  ])
  software.value = s?.total ?? null
  findings.value = v?.total ?? null
}

function onTab(e: Event): void {
  const tab = tabs.value[(e as CustomEvent<number>).detail - 1]
  if (tab) void router.push({ name: tab.name, params: { id: props.deviceId }, query: route.query })
}

watch(() => props.deviceId, loadCounts)
onMounted(() => {
  void loadCounts()
  window.addEventListener('paddock:tab', onTab)
})
onBeforeUnmount(() => window.removeEventListener('paddock:tab', onTab))
</script>

<template>
  <v-tabs
    class="pd-device-tabs"
    color="primary"
    density="compact"
    show-arrows
    :aria-label="t('inventory.deviceTabs')"
  >
    <v-tab
      v-for="tab in tabs"
      :key="tab.name"
      :to="{ name: tab.name, params: { id: deviceId }, query: route.query }"
      :data-testid="tab.testid"
      exact
    >
      {{ t(tab.label) }}
      <span
        v-if="tab.name === 'device-software' && software !== null"
        class="pd-tab-count pd-muted"
      >{{ software }}</span>
      <span
        v-if="tab.name === 'device-vulnerabilities' && findings !== null"
        class="pd-tab-count"
        :class="findings > 0 ? 'pd-tab-count--critical' : 'pd-muted'"
      >{{ findings }}</span>
    </v-tab>
  </v-tabs>
</template>
