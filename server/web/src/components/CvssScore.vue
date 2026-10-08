<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { formatScore } from '../lib/inventory'

/** A CVSS score with the CVSS vector of Ubuntu's data as tooltip (plan M5c decision 5); keyboard users focus it. */
defineProps<{ score: number | null | undefined, vector: string | null | undefined }>()
const { t } = useI18n()
</script>

<template>
  <v-tooltip
    v-if="vector"
    :text="vector"
    location="top"
  >
    <template #activator="{ props: activator }">
      <span
        v-bind="activator"
        class="cvss"
        tabindex="0"
        :aria-label="t('inventory.cvssVector', { score: formatScore(score), vector })"
        data-testid="cvss-vector"
      >{{ formatScore(score) }} <v-icon
        icon="$info"
        size="small"
      /></span>
    </template>
  </v-tooltip>
  <span v-else>{{ formatScore(score) }}</span>
</template>

<style scoped>
.cvss {
  cursor: help;
}
</style>
