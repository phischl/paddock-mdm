<script setup lang="ts">
import type { Status } from '../lib/status'

/** A status chip (plan M7c decision 19): a dot and a label, never colour alone; not a button. */
defineProps<{
  status: Status
  label: string
  /** Tooltip: the absolute time or an explanation. */
  title?: string
}>()
</script>

<template>
  <span
    class="pd-chip"
    :class="'pd-chip--' + status"
    :title="title"
  >
    <span
      class="pd-chip-dot"
      aria-hidden="true"
    />
    <slot>{{ label }}</slot>
  </span>
</template>
