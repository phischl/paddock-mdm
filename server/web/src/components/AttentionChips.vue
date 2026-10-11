<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { AttentionCondition } from '../api/client'
import { attentionStatus } from '../lib/status'
import StatusChip from './StatusChip.vue'

/**
 * The open conditions of a device as chips, most severe first as the API orders them (plan M7c decision 33): at
 * most three, then a "+n" chip whose tooltip names the rest; a condition's detail is its chip's tooltip.
 */
defineProps<{ conditions: AttentionCondition[] }>()
const { t } = useI18n()
const maxChips = 3
</script>

<template>
  <span class="pd-chips">
    <StatusChip
      v-for="c in conditions.slice(0, maxChips)"
      :key="c.kind"
      :status="attentionStatus(c.kind).status"
      :label="t(attentionStatus(c.kind).label)"
      :title="c.detail || undefined"
    />
    <StatusChip
      v-if="conditions.length > maxChips"
      status="neutral"
      :label="t('attention.more', { count: conditions.length - maxChips })"
      :title="conditions.slice(maxChips).map((c) => t('attention.kinds.' + c.kind)).join(', ')"
    />
  </span>
</template>
