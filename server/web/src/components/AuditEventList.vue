<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { AuditEvent } from '../api/client'
import { auditFilters } from '../lib/audit'
import { auditText } from '../lib/format'
import type { ListColumn, ListParams, Page } from '../lib/listQuery'
import { outcomeStatus } from '../lib/status'
import ActorChip from './ActorChip.vue'
import DataList from './DataList.vue'
import StatusChip from './StatusChip.vue'
import TimeCell from './TimeCell.vue'

/**
 * The audit events as a list (plan M7c decisions 32 and 34): time, actor chip, the sentence, the device, the code
 * and the outcome chip; a row expands to the stored fields, never translated. The device tab leaves out the device
 * column. Events are shown as stored; only the device name is resolved at read time by the server.
 */
const props = withDefaults(
  defineProps<{ fetch: (p: ListParams) => Promise<Page<AuditEvent>>; showDevice?: boolean }>(),
  { showDevice: true },
)
const { t, te } = useI18n()

const columns = computed<ListColumn[]>(() => [
  { key: 'occurred_at', title: 'audit.time', sortable: true, role: 'meta' },
  { key: 'actor', title: 'audit.actor', role: 'meta' },
  { key: 'event', title: 'audit.event', role: 'primary' },
  ...(props.showDevice ? [{ key: 'device', title: 'audit.deviceColumn', role: 'meta', mono: true, hideBelow: 'sm' } as ListColumn] : []),
  { key: 'code', title: 'audit.codeColumn', sortable: true, role: 'meta', mono: true, hideBelow: 'md' },
  { key: 'outcome', title: 'audit.outcome', sortable: true, role: 'status' },
])

/** The stored fields of an event for the expanded row, as stored. */
function details(e: AuditEvent): [string, string][] {
  const rows: [string, string][] = [
    ['event_id', e.event_id], ['correlation_id', e.correlation_id], ['source', e.source],
    ['actor_ip', e.actor.ip ?? '–'], ['step_up', String(e.actor.step_up)], ['error_code', e.error_code ?? '–'],
  ]
  for (const [k, v] of Object.entries(e.params)) rows.push(['params.' + k, typeof v === 'string' ? v : JSON.stringify(v)])
  return rows
}
</script>

<template>
  <DataList
    :columns="columns"
    :fetch="fetch"
    :filters="auditFilters"
    searchable
    expandable
    default-sort="-occurred_at"
    item-value="event_id"
    empty-icon="scroll-text"
    empty-title="audit.empty.title"
    empty-description="audit.empty.description"
  >
    <template #[`item.occurred_at`]="{ item }: { item: AuditEvent }">
      <TimeCell
        :iso="item.occurred_at"
        precision="second"
      />
    </template>
    <template #[`item.actor`]="{ item }: { item: AuditEvent }">
      <ActorChip
        :actor="item.actor"
        :source="item.source"
      />
    </template>
    <template #[`item.event`]="{ item }: { item: AuditEvent }">
      <span
        class="audit-text"
        :data-code="item.code"
      >{{ auditText(t, te, item) }}</span>
    </template>
    <template #[`item.device`]="{ item }: { item: AuditEvent }">
      <RouterLink
        v-if="item.device"
        :to="{ name: 'device', params: { id: item.device.id } }"
        class="mono"
      >
        {{ item.device.hostname ?? item.device.id }}
      </RouterLink>
      <span
        v-else
        class="pd-muted"
      >–</span>
    </template>
    <template #[`item.code`]="{ item }: { item: AuditEvent }">
      <span class="mono">{{ item.code }}</span>
    </template>
    <template #[`item.outcome`]="{ item }: { item: AuditEvent }">
      <StatusChip
        class="outcome"
        :status="outcomeStatus(item.outcome).status"
        :label="t(outcomeStatus(item.outcome).label)"
      />
    </template>
    <template #expanded="{ item }: { item: AuditEvent }">
      <dl data-testid="audit-details">
        <template
          v-for="[k, v] in details(item)"
          :key="k"
        >
          <dt>{{ te('audit.details.' + k) ? t('audit.details.' + k) : k }}</dt>
          <dd>{{ v }}</dd>
        </template>
      </dl>
    </template>
  </DataList>
</template>
