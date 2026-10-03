<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import { auditCodes, useAuditLog } from '../lib/audit'
import { auditText, formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'

const { t, te, locale } = useI18n()
const problemText = useProblemText()
const log = useAuditLog()

const codeOptions = computed(() => [
  { label: t('audit.allCodes'), value: '' },
  ...auditCodes.map((c) => ({ label: c, value: c })),
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
      <div class="field">
        <label for="audit-from">{{ t('audit.from') }}</label>
        <InputText
          id="audit-from"
          v-model="log.from.value"
          type="date"
        />
      </div>
      <div class="field">
        <label for="audit-to">{{ t('audit.to') }}</label>
        <InputText
          id="audit-to"
          v-model="log.to.value"
          type="date"
        />
      </div>
      <div class="field">
        <label
          id="audit-code-label"
          for="audit-code"
        >{{ t('audit.code') }}</label>
        <Select
          v-model="log.code.value"
          input-id="audit-code"
          aria-labelledby="audit-code-label"
          :options="codeOptions"
          option-label="label"
          option-value="value"
        />
      </div>
      <Button
        type="submit"
        :label="t('common.apply')"
      />
    </form>
    <p
      v-if="log.error.value"
      class="form-error"
      role="alert"
    >
      {{ problemText(log.error.value) }}
    </p>
    <DataTable
      :value="log.items.value"
      data-key="event_id"
      :loading="log.loading.value"
      class="table"
      data-testid="audit-table"
    >
      <template #empty>
        {{ t('common.empty') }}
      </template>
      <Column :header="t('audit.time')">
        <template #body="{ data }">
          {{ formatDateTime(data.occurred_at, locale) }}
        </template>
      </Column>
      <Column :header="t('audit.event')">
        <template #body="{ data }">
          <span
            class="audit-text"
            :data-code="data.code"
          >{{ auditText(t, te, data) }}</span>
        </template>
      </Column>
      <Column :header="t('audit.outcome')">
        <template #body="{ data }">
          <span :class="'outcome outcome-' + data.outcome">{{ t('audit.outcomes.' + data.outcome) }}</span>
        </template>
      </Column>
      <Column :header="t('audit.actor')">
        <template #body="{ data }">
          {{ data.actor.display ?? data.actor.type }}
        </template>
      </Column>
    </DataTable>
    <Button
      v-if="log.nextCursor.value"
      :label="t('common.loadMore')"
      severity="secondary"
      @click="log.load(true)"
    />
  </section>
</template>
