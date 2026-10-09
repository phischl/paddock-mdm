<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import ChangeSetPlan from '../components/ChangeSetPlan.vue'
import DataList from '../components/DataList.vue'
import type { ChangeSet } from '../api/client'
import { changeSetFilters, listChangeSets } from '../lib/changeSets'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'

const { t, locale } = useI18n()
const selected = ref<ChangeSet | null>(null)

const columns = computed<ListColumn[]>(() => [
  { key: 'applied_at', title: 'changeSets.appliedAt', sortable: true },
  { key: 'actor', title: 'changeSets.actor' },
  { key: 'source', title: 'changeSets.source' },
  { key: 'created', title: 'changeSets.created' },
  { key: 'updated', title: 'changeSets.updated' },
  { key: 'deleted', title: 'changeSets.deleted' },
  { key: 'actions', title: 'common.actions' },
])
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('changeSets.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('changeSets.summary') }}
    </p>
    <DataList
      :columns="columns"
      :fetch="listChangeSets"
      :filters="changeSetFilters"
      searchable
      default-sort="-applied_at"
      item-value="id"
      data-testid="change-set-list"
    >
      <template #[`item.applied_at`]="{ item }: { item: ChangeSet }">
        {{ formatDateTime(item.applied_at, locale) }}
      </template>
      <template #[`item.actor`]="{ item }: { item: ChangeSet }">
        {{ item.actor.display }}
      </template>
      <template #[`item.source`]="{ item }: { item: ChangeSet }">
        <v-chip
          size="small"
          variant="tonal"
        >
          {{ t('changeSets.sources.' + item.source) }}
        </v-chip>
      </template>
      <template #[`item.created`]="{ item }: { item: ChangeSet }">
        {{ item.summary.created }}
      </template>
      <template #[`item.updated`]="{ item }: { item: ChangeSet }">
        {{ item.summary.updated }}
      </template>
      <template #[`item.deleted`]="{ item }: { item: ChangeSet }">
        {{ item.summary.deleted }}
      </template>
      <template #[`item.actions`]="{ item }: { item: ChangeSet }">
        <v-btn
          size="small"
          variant="tonal"
          :aria-label="t('changeSets.detailsLabel', { at: formatDateTime(item.applied_at, locale) })"
          @click="selected = item"
        >
          {{ t('changeSets.details') }}
        </v-btn>
      </template>
    </DataList>

    <v-dialog
      :model-value="!!selected"
      max-width="64rem"
      :aria-label="t('changeSets.detailsTitle')"
      @update:model-value="(v: boolean) => !v && (selected = null)"
    >
      <v-card
        v-if="selected"
        :title="t('changeSets.detailsTitle')"
      >
        <v-card-text>
          <p>
            {{ t('changeSets.detailsSummary', { actor: selected.actor.display, at: formatDateTime(selected.applied_at, locale) }) }}
          </p>
          <ChangeSetPlan :plan="selected.plan" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn
            color="primary"
            @click="selected = null"
          >
            {{ t('changeSets.close') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </section>
</template>
