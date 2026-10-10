<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import { listDeviceSoftware } from '../lib/inventory'
import type { ListColumn } from '../lib/listQuery'

const { t } = useI18n()
const route = useRoute()
const id = computed(() => String(route.params.id))
const fetch = computed(() => listDeviceSoftware(id.value))
const columns: ListColumn[] = [
  { key: 'name', title: 'inventory.package', sortable: true },
  { key: 'version', title: 'inventory.version', sortable: true },
  { key: 'source', title: 'inventory.source' },
]
</script>

<template>
  <div class="pd-device-tab">
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
  </div>
</template>
