<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { clientPage, type ReviewRow, type ReviewSection } from '../lib/accessReview'
import type { ListParams } from '../lib/listQuery'
import DataList from './DataList.vue'
import TimeCell from './TimeCell.vue'

/**
 * One expandable card of the access review: the rows of a section as a DataList, searched, sorted and paged in the
 * browser because the report is one response. The list state lives in the route query under the section's key.
 */
const props = defineProps<{ section: ReviewSection }>()
const { t } = useI18n()

const fetchRows = (p: ListParams) => Promise.resolve(clientPage(props.section.rows, p))
const flag = (item: ReviewRow, key: string) => (item[key] === true ? t('accessReview.yes') : t('accessReview.no'))
</script>

<template>
  <v-expansion-panel
    :data-testid="`review-${section.key}`"
    :title="t(section.title) + ' (' + section.total + ')'"
  >
    <v-expansion-panel-text>
      <p
        v-if="section.note"
        class="pd-muted"
      >
        {{ t(section.note.key, section.note.params) }}
      </p>
      <p
        v-if="section.total > section.rows.length"
        class="form-error"
        role="status"
        data-testid="review-cap"
      >
        {{ t('accessReview.capNotice', { shown: section.rows.length, total: section.total }) }}
      </p>
      <DataList
        :columns="section.columns"
        :fetch="fetchRows"
        :query-prefix="section.key"
        :default-sort="section.defaultSort"
        item-value="__row"
        searchable
        empty-icon="scroll-text"
        empty-title="accessReview.empty.title"
        empty-description="accessReview.empty.description"
      >
        <template
          v-for="c in section.columns.filter((x) => x.kind)"
          :key="c.key"
          #[`item.${c.key}`]="{ item }: { item: ReviewRow }"
        >
          <template v-if="c.kind === 'time'">
            <TimeCell
              v-if="typeof item[c.key] === 'string'"
              :iso="item[c.key] as string"
            />
            <span
              v-else
              class="pd-muted"
            >–</span>
          </template>
          <template v-else>
            {{ flag(item, c.key) }}
          </template>
        </template>
      </DataList>
    </v-expansion-panel-text>
  </v-expansion-panel>
</template>
