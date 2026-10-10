<script setup lang="ts">
import type { IconName } from '../lib/icons.gen'
import PdIcon from './PdIcon'

/** An empty list (plan M7c decision 22): what the list is for and, when the role may act, the next step. */
defineProps<{
  icon: IconName
  title: string
  description: string
}>()
</script>

<template>
  <div
    class="pd-empty"
    data-testid="empty-state"
  >
    <PdIcon
      :name="icon"
      :size="24"
    />
    <p class="pd-type-section pd-empty-title">
      {{ title }}
    </p>
    <p class="pd-muted pd-empty-text">
      {{ description }}
    </p>
    <div
      v-if="$slots.default"
      class="pd-empty-action"
    >
      <slot />
    </div>
  </div>
</template>
