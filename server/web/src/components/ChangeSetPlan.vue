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
  <!-- The plan is wider than a phone and can be long: it scrolls in its own region, which keyboard users reach and
       screen readers name (axe scrollable-region-focusable); the page itself never scrolls sideways. -->
  <div
    class="plan-scroll"
    role="region"
    tabindex="0"
    :aria-label="t('changeSets.planRegion')"
    data-testid="change-set-plan-region"
  >
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
          <td class="plan-nowrap">
            {{ row.section }}
          </td>
          <td><code>{{ row.key }}</code></td>
          <td class="plan-nowrap">
            {{ t('changeSets.actions.' + row.action) }}
          </td>
          <td>{{ row.field }}</td>
          <td><code>{{ row.before }}</code></td>
          <td><code>{{ row.after }}</code></td>
        </tr>
      </tbody>
    </v-table>
  </div>
</template>

<style scoped>
.plan-scroll {
  max-height: 60vh;
  max-width: 100%;
  overflow: auto;
}

/* The region scrolls; Vuetify's own wrapper would be a second, unnamed scroll area inside it. */
.plan-scroll :deep(.v-table__wrapper) {
  overflow: visible;
}

/* Short labels stay whole instead of being squeezed into one letter per line on a phone. */
.plan-nowrap {
  white-space: nowrap;
}
</style>
