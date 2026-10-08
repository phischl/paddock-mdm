<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ConfigPlan } from '../api/client'
import { planRows } from '../lib/changeSets'

const props = defineProps<{ plan: ConfigPlan }>()
const { t } = useI18n()
const rows = computed(() => planRows(props.plan))
</script>

<template>
  <v-table
    density="compact"
    data-testid="change-set-plan"
  >
    <thead>
      <tr>
        <th scope="col">
          {{ t('changeSets.section') }}
        </th>
        <th scope="col">
          {{ t('changeSets.key') }}
        </th>
        <th scope="col">
          {{ t('changeSets.action') }}
        </th>
        <th scope="col">
          {{ t('changeSets.field') }}
        </th>
        <th scope="col">
          {{ t('changeSets.before') }}
        </th>
        <th scope="col">
          {{ t('changeSets.after') }}
        </th>
      </tr>
    </thead>
    <tbody>
      <tr
        v-for="(row, i) in rows"
        :key="i"
      >
        <td>{{ row.section }}</td>
        <td><code>{{ row.key }}</code></td>
        <td>{{ t('changeSets.actions.' + row.action) }}</td>
        <td>{{ row.field }}</td>
        <td><code>{{ row.before }}</code></td>
        <td><code>{{ row.after }}</code></td>
      </tr>
    </tbody>
  </v-table>
</template>
