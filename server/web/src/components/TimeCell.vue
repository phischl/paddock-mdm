<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatAbsolute, formatAbsoluteFull, formatRelative } from '../lib/time'

/** A timestamp in a table (plan M7c decision 20): mono, one line, the full value in the tooltip. */
const props = withDefaults(
  defineProps<{
    iso: string
    mode?: 'absolute' | 'relative'
    precision?: 'minute' | 'second'
  }>(),
  { mode: 'absolute', precision: 'minute' },
)
const { locale } = useI18n()
const text = computed(() =>
  props.mode === 'relative' ? formatRelative(props.iso, new Date(), locale.value) : formatAbsolute(props.iso, new Date(), props.precision),
)
</script>

<template>
  <time
    :datetime="iso"
    :title="formatAbsoluteFull(iso)"
    class="pd-time mono"
  >{{ text }}</time>
</template>
