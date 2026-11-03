<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceSoftwareState } from '../api/client'
import { softwareState } from '../lib/software'
import StatusChip from './StatusChip.vue'

/**
 * The state of an application on a device as a chip (plan M13a decision 32). A pending state explains itself with the
 * reason, a failed one with the reason and the error the agent reported, in the tooltip.
 */
const props = defineProps<{ state: DeviceSoftwareState; reason?: string; error?: string }>()
const { t, te } = useI18n()
const view = computed(() => softwareState(props.state))
const reasonText = computed(() => (props.reason && te('software.reason.' + props.reason) ? t('software.reason.' + props.reason) : (props.reason ?? '')))
const title = computed(() => {
  if (props.state === 'pending') return reasonText.value || undefined
  if (props.state === 'failed') return [reasonText.value, props.error ?? ''].filter((x) => x !== '').join(' - ') || undefined
  return undefined
})
</script>

<template>
  <StatusChip
    :status="view.status"
    :label="t(view.label)"
    :title="title"
  />
</template>
