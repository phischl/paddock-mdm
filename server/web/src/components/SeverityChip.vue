<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { Severity } from '../api/client'

/**
 * The severity of a finding as a chip on the severity scale (ADR 0020, plan M7c decision 7): Ubuntu's priority;
 * unknown is a finding Ubuntu has not rated. A dot and a label, never colour alone.
 */
defineProps<{ severity: Severity }>()
const { t } = useI18n()
</script>

<template>
  <span
    class="pd-chip"
    :class="'pd-chip--sev-' + severity"
    :data-severity="severity"
  >
    <span
      class="pd-chip-dot"
      aria-hidden="true"
    />
    {{ t('inventory.severities.' + severity) }}
  </span>
</template>
