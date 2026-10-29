<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { AuditEvent } from '../api/client'
import { actorStatus, sourceStatus } from '../lib/status'
import StatusChip from './StatusChip.vue'

/**
 * The actor of an audit event (plan M7c decision 34): a type chip followed by the display name in mono; events of an
 * MCP session add the MCP chip and the client name (ADR 0044).
 */
const props = defineProps<{ actor: AuditEvent['actor']; source: AuditEvent['source'] }>()
const { t } = useI18n()
const channel = computed(() => sourceStatus(props.source))
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
    <StatusChip
      v-if="channel"
      :status="channel.status"
      :label="t(channel.label)"
      data-testid="actor-source"
    />
    <span
      v-if="channel && actor.client"
      class="mono"
      data-testid="actor-client"
    >{{ actor.client }}</span>
  </span>
</template>
