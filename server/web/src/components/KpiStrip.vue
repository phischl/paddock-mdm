<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { KpiCell } from '../lib/overview'

/** The KPI strip of the overview (plan M7c decision 28): one bordered panel, a cell per number, linked to its list. */
defineProps<{ cells: KpiCell[] }>()
const { t } = useI18n()
</script>

<template>
  <div
    class="pd-kpis pd-panel"
    data-testid="overview-kpis"
  >
    <component
      :is="cell.to ? 'RouterLink' : 'div'"
      v-for="cell in cells"
      :key="cell.key"
      :to="cell.to"
      class="pd-kpi"
      :class="{ 'pd-kpi--link': !!cell.to }"
      :data-testid="'kpi-' + cell.key"
    >
      <span class="pd-type-label pd-kpi-label">
        <span
          class="pd-kpi-dot"
          :class="'pd-kpi-dot--' + cell.status"
          aria-hidden="true"
        />
        {{ t(cell.label) }}
      </span>
      <span class="pd-type-kpi pd-tabular">{{ cell.value }}</span>
      <span class="pd-type-caption pd-muted">{{ t(cell.note, cell.noteValues) }}</span>
    </component>
  </div>
</template>
