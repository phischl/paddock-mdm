<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import DeviceTabs from '../components/DeviceTabs.vue'
import { getDevice } from '../lib/devices'
import { listDeviceSoftware } from '../lib/inventory'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'

const { t } = useI18n()
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
const fetch = computed(() => listDeviceSoftware(id.value))
const columns: ListColumn[] = [
  { key: 'name', title: 'inventory.package', sortable: true },
  { key: 'version', title: 'inventory.version', sortable: true },
  { key: 'source', title: 'inventory.source' },
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
        {{ t('inventory.softwareHint') }}
      </p>
      <DataList
        :columns="columns"
        :fetch="fetch"
        searchable
        default-sort="name"
        item-value="key"
        data-testid="device-software-list"
      />
    </template>
  </section>
</template>
