<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { OverviewSeverityBuckets } from '../api/client'
import { severitySegments } from '../lib/overview'

/**
 * Devices by their worst finding as one stacked bar (plan M7c decision 28): the bar is an image whose label lists
 * every segment; the legend beneath carries the same numbers as links to the filtered vulnerability list.
 */
const props = defineProps<{ buckets: OverviewSeverityBuckets }>()
const { t } = useI18n()
const segments = computed(() => severitySegments(props.buckets))
const total = computed(() => segments.value.reduce((n, s) => n + s.count, 0))
const label = (level: string) => t('overview.vulnerabilities.levels.' + level)
const ariaLabel = computed(() =>
  t('overview.vulnerabilities.barLabel', {
    segments: segments.value.map((s) => t('overview.vulnerabilities.segment', { level: label(s.level), count: s.count })).join(', '),
  }),
)
</script>

<template>
  <div class="pd-sevbar">
    <div
      class="pd-sevbar-track"
      role="img"
      :aria-label="ariaLabel"
      data-testid="severity-bar"
    >
      <template
        v-for="s in segments"
        :key="s.level"
      >
        <span
          v-if="s.count > 0"
          class="pd-sevbar-segment"
          :class="'pd-sevbar-segment--' + s.level"
          :style="{ flexGrow: s.count }"
        />
      </template>
      <span
        v-if="total === 0"
        class="pd-sevbar-segment pd-sevbar-segment--empty"
      />
    </div>
    <ul class="pd-sevbar-legend">
      <li
        v-for="s in segments"
        :key="s.level"
      >
        <component
          :is="s.to ? 'RouterLink' : 'span'"
          :to="s.to"
          class="pd-sevbar-item"
        >
          <span
            class="pd-sevbar-dot"
            :class="'pd-sevbar-segment--' + s.level"
            aria-hidden="true"
          />
          {{ label(s.level) }}
          <span class="pd-tabular mono">{{ s.count }}</span>
        </component>
      </li>
    </ul>
  </div>
</template>
