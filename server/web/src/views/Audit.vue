<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { auditCodes, useAuditLog } from '../lib/audit'
import { auditText, formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'

const { t, te, locale } = useI18n()
const problemText = useProblemText()
const log = useAuditLog()

const codeOptions = computed(() => [
  { title: t('audit.allCodes'), value: '' },
  ...auditCodes.map((c) => ({ title: c, value: c })),
])
const headers = computed(() => [
  { title: t('audit.time'), key: 'occurred_at', sortable: false },
  { title: t('audit.event'), key: 'code', sortable: false },
  { title: t('audit.outcome'), key: 'outcome', sortable: false },
  { title: t('audit.actor'), key: 'actor', sortable: false },
])

onMounted(() => log.load())
</script>

<template>
  <section class="page">
    <h1>{{ t('audit.title') }}</h1>
    <form
      class="filters"
      @submit.prevent="log.load()"
    >
      <v-text-field
        id="audit-from"
        v-model="log.from.value"
        :label="t('audit.from')"
        type="date"
        hide-details
      />
      <v-text-field
        id="audit-to"
        v-model="log.to.value"
        :label="t('audit.to')"
        type="date"
        hide-details
      />
      <v-select
        id="audit-code"
        v-model="log.code.value"
        :label="t('audit.code')"
        :items="codeOptions"
        hide-details
      />
      <v-btn
        type="submit"
        color="primary"
      >
        {{ t('common.apply') }}
      </v-btn>
    </form>
    <p
      v-if="log.error.value"
      class="form-error"
      role="alert"
    >
      {{ problemText(log.error.value) }}
    </p>
    <v-data-table
      :headers="headers"
      :items="log.items.value"
      item-value="event_id"
      :items-per-page="-1"
      :loading="log.loading.value"
      hide-default-footer
      class="table"
      data-testid="audit-table"
    >
      <template #no-data>
        {{ t('common.empty') }}
      </template>
      <template #[`item.occurred_at`]="{ item }">
        {{ formatDateTime(item.occurred_at, locale) }}
      </template>
      <template #[`item.code`]="{ item }">
        <span
          class="audit-text"
          :data-code="item.code"
        >{{ auditText(t, te, item) }}</span>
      </template>
      <template #[`item.outcome`]="{ item }">
        <span :class="'outcome outcome-' + item.outcome">{{ t('audit.outcomes.' + item.outcome) }}</span>
      </template>
      <template #[`item.actor`]="{ item }">
        {{ item.actor.display ?? item.actor.type }}
      </template>
    </v-data-table>
    <v-btn
      v-if="log.hasMore.value"
      variant="tonal"
      @click="log.load(true)"
    >
      {{ t('common.loadMore') }}
    </v-btn>
  </section>
</template>
