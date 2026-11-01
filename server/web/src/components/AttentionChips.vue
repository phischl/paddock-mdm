<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { AttentionCondition } from '../api/client'
import { attentionStatus, findingStatus } from '../lib/status'
import StatusChip from './StatusChip.vue'

/**
 * The open conditions of a device as chips, most severe first as the API orders them (plan M7c decision 33): at
 * most three, then a "+n" chip whose tooltip names the rest; a condition's detail is its chip's tooltip. A condition with a finding is followed by the finding's status chip
 * (plan M9 decision 35), whose tooltip names the assignee.
 */
defineProps<{ conditions: AttentionCondition[] }>()
const { t } = useI18n()
const maxChips = 3
</script>

<template>
  <span class="pd-chips">
    <template
      v-for="c in conditions.slice(0, maxChips)"
      :key="c.kind"
    >
      <StatusChip
        :status="attentionStatus(c.kind).status"
        :label="t(attentionStatus(c.kind).label)"
        :title="c.detail || undefined"
      />
      <StatusChip
        v-if="c.finding"
        :status="findingStatus(c.finding.status).status"
        :label="t(findingStatus(c.finding.status).label)"
        :title="c.finding.assignee_display || undefined"
        data-testid="condition-finding"
      />
    </template>
    <StatusChip
      v-if="conditions.length > maxChips"
      status="neutral"
      :label="t('attention.more', { count: conditions.length - maxChips })"
      :title="conditions.slice(maxChips).map((c) => t('attention.kinds.' + c.kind)).join(', ')"
    />
  </span>
</template>
