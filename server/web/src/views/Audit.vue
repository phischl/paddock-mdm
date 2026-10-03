<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import type { AuditEvent } from '../api/client'
import { auditFilters, listAuditEvents } from '../lib/audit'
import { auditText, formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'

const { t, te, locale } = useI18n()

const columns: ListColumn[] = [
  { key: 'occurred_at', title: 'audit.time', sortable: true },
  { key: 'code', title: 'audit.event', sortable: true },
  { key: 'outcome', title: 'audit.outcome', sortable: true },
  { key: 'actor', title: 'audit.actor' },
]
</script>

<template>
  <section class="page">
    <h1>{{ t('audit.title') }}</h1>
    <DataList
      :columns="columns"
      :fetch="listAuditEvents"
      :filters="auditFilters"
      searchable
      default-sort="-occurred_at"
      item-value="event_id"
      data-testid="audit-table"
    >
      <template #[`item.occurred_at`]="{ item }: { item: AuditEvent }">
        {{ formatDateTime(item.occurred_at, locale) }}
      </template>
      <template #[`item.code`]="{ item }: { item: AuditEvent }">
        <span
          class="audit-text"
          :data-code="item.code"
        >{{ auditText(t, te, item) }}</span>
      </template>
      <template #[`item.outcome`]="{ item }: { item: AuditEvent }">
        <span :class="'outcome outcome-' + item.outcome">{{ t('audit.outcomes.' + item.outcome) }}</span>
      </template>
      <template #[`item.actor`]="{ item }: { item: AuditEvent }">
        {{ item.actor.display ?? item.actor.type }}
      </template>
    </DataList>
  </section>
</template>
