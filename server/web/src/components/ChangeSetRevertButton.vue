<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ChangeSet } from '../api/client'
import { revertBlocked } from '../lib/changeSets'

/** The Revert action of a change set (plan M11 decision 22); disabled with the reason as tooltip when it cannot be reverted. */
const props = defineProps<{ changeSet: ChangeSet; label: string }>()
const emit = defineEmits<{ revert: [] }>()
const { t } = useI18n()
const blocked = computed(() => revertBlocked(props.changeSet))
const reason = computed(() => (blocked.value ? t('changeSets.revert.blocked.' + blocked.value) : ''))
</script>

<template>
  <!-- Named like the tooltips in Devices.vue and CvssScore.vue: axe needs the name while the tooltip is hidden. -->
  <v-tooltip
    v-if="blocked"
    :text="reason"
    :aria-label="reason"
    location="top"
  >
    <template #activator="{ props: tip }">
      <!-- A disabled button gets no pointer or focus events; the wrapper carries the tooltip and stays focusable. -->
      <span
        v-bind="tip"
        tabindex="0"
        :aria-label="label + ': ' + reason"
        data-testid="change-set-revert-blocked"
      >
        <v-btn
          size="small"
          variant="tonal"
          color="error"
          disabled
          :aria-label="label"
        >
          {{ t('changeSets.revert.action') }}
        </v-btn>
      </span>
    </template>
  </v-tooltip>
  <v-btn
    v-else
    size="small"
    variant="tonal"
    color="error"
    :aria-label="label"
    data-testid="change-set-revert"
    @click="emit('revert')"
  >
    {{ t('changeSets.revert.action') }}
  </v-btn>
</template>
