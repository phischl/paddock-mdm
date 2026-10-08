<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { Severity } from '../api/client'

/** The severity of a finding as a chip: Ubuntu's priority (ADR 0020); unknown is a finding Ubuntu has not rated. */
defineProps<{ severity: Severity }>()
const { t } = useI18n()
const colors: Record<Severity, string> = { critical: 'error', high: 'warning', medium: 'info', low: 'success', unknown: 'default' }
</script>

<template>
  <v-chip
    size="small"
    :color="colors[severity]"
    variant="tonal"
  >
    {{ t('inventory.severities.' + severity) }}
  </v-chip>
</template>
