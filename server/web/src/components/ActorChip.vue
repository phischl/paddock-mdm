<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { AuditEvent } from '../api/client'
import { actorStatus } from '../lib/status'
import StatusChip from './StatusChip.vue'

/** The actor of an audit event (plan M7c decision 34): a type chip followed by the display name in mono. */
defineProps<{ actor: AuditEvent['actor'] }>()
const { t } = useI18n()
</script>

<template>
  <span class="pd-actor">
    <StatusChip
      :status="actorStatus(actor.type).status"
      :label="t(actorStatus(actor.type).label)"
    />
    <span
      v-if="actor.display"
      class="mono"
    >{{ actor.display }}</span>
  </span>
</template>
