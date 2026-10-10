<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

/** The status card of the IP allow list page (plan M7a decision 25): the caller's address and what the list does to it. */
const props = defineProps<{
  clientIp: string
  entries: number
  covering: string[]
}>()

const { t } = useI18n()
const state = computed(() => (props.entries === 0 ? 'off' : props.covering.length > 0 ? 'covered' : 'notCovered'))
</script>

<template>
  <v-alert
    :type="state === 'notCovered' ? 'warning' : 'info'"
    variant="tonal"
    data-testid="ip-allowlist-status"
    :data-state="state"
  >
    <p>{{ t('ipAllowlist.yourAddress', { ip: clientIp }) }}</p>
    <p v-if="state === 'off'">
      {{ t('ipAllowlist.statusOff') }}
    </p>
    <p v-else-if="state === 'covered'">
      {{ t('ipAllowlist.statusCovered', { count: entries, cidrs: covering.join(', ') }) }}
    </p>
    <p
      v-else
      class="status-warning"
    >
      {{ t('ipAllowlist.statusNotCovered', { count: entries }) }}
    </p>
  </v-alert>
</template>

<style scoped>
.status-warning { font-weight: 600; }
</style>
