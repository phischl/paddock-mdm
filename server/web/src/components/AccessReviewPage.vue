<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import AccessReviewSection from './AccessReviewSection.vue'
import EmptyState from './EmptyState.vue'
import TimeCell from './TimeCell.vue'
import {
  customRangeError, exportUrl, getAccessReview, getPlatformAccessReview, organizationSections, platformSections, presets,
  resolvePeriod, type ReviewScope, type ReviewSection,
} from '../lib/accessReview'
import { useProblemText } from '../lib/problems'

/**
 * The access review page of an organization or of the platform (plan M12 decision 27): a period (presets or custom,
 * kept in the route query), one expandable card per section of the report, and the exports. The period of the view and
 * of the export buttons is resolved once per load, so the files cover what the page shows.
 */
const props = defineProps<{ scope: ReviewScope }>()
const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const problemText = useProblemText()

const period = computed(() => resolvePeriod(route.query, loaded.value))
const loaded = ref(new Date())
const sections = ref<ReviewSection[]>([])
const stepUp = ref<{ succeeded: number; failed: number } | null>(null)
const generatedAt = ref('')
const problem = ref('')
const customFrom = ref('')
const customTo = ref('')
const customError = ref('')
const loadedFor = ref('')
let request = 0

const title = computed(() => t(props.scope === 'platform' ? 'accessReview.platformTitle' : 'accessReview.title'))
const rangeKey = computed(() => `${route.query.days ?? ''}|${route.query.from ?? ''}|${route.query.to ?? ''}`)
const shownError = computed(() => customError.value || period.value.error)

async function load(): Promise<void> {
  const current = ++request
  problem.value = ''
  sections.value = []
  stepUp.value = null
  if (period.value.error !== '') return
  const result = props.scope === 'platform' ? await getPlatformAccessReview(period.value) : await getAccessReview(period.value)
  if (current !== request) return
  if (typeof result === 'string') {
    problem.value = result
    return
  }
  generatedAt.value = result.generated_at
  if ('step_up' in result) {
    stepUp.value = result.step_up
    sections.value = organizationSections(result)
  } else {
    sections.value = platformSections(result)
  }
  loadedFor.value = rangeKey.value
}

watch(
  rangeKey,
  () => {
    loaded.value = new Date()
    customFrom.value = period.value.fromDay
    customTo.value = period.value.toDay
    customError.value = ''
    void load()
  },
  { immediate: true },
)

/** A preset replaces the whole period query and keeps the foreign keys of the section lists out of the way. */
function choose(days: number): void {
  void router.push({ query: { days: String(days) } })
}

function applyCustom(): void {
  customError.value = customRangeError(customFrom.value, customTo.value)
  if (customError.value !== '') return
  void router.push({ query: { from: customFrom.value, to: customTo.value } })
}
</script>

<template>
  <section class="page">
    <h1>{{ title }}</h1>
    <p class="pd-muted">
      {{ t(scope === 'platform' ? 'accessReview.platformIntro' : 'accessReview.intro') }}
    </p>

    <div
      class="period"
      role="group"
      :aria-label="t('accessReview.period.label')"
      data-testid="review-period"
    >
      <v-btn
        v-for="days in presets"
        :key="days"
        :variant="period.preset === days ? 'flat' : 'tonal'"
        :color="period.preset === days ? 'primary' : undefined"
        :aria-pressed="period.preset === days"
        :data-testid="`preset-${days}`"
        @click="choose(days)"
      >
        {{ t('accessReview.period.days', { days }) }}
      </v-btn>
      <v-text-field
        v-model="customFrom"
        :label="t('accessReview.period.from')"
        type="date"
        hide-details
        data-testid="custom-from"
      />
      <v-text-field
        v-model="customTo"
        :label="t('accessReview.period.to')"
        type="date"
        hide-details
        data-testid="custom-to"
      />
      <v-btn
        :variant="period.preset === 'custom' ? 'flat' : 'tonal'"
        :color="period.preset === 'custom' ? 'primary' : undefined"
        data-testid="custom-apply"
        @click="applyCustom"
      >
        {{ t('accessReview.period.apply') }}
      </v-btn>
    </div>
    <p
      v-if="shownError"
      class="form-error"
      role="alert"
      data-testid="review-period-error"
    >
      {{ t(shownError) }}
    </p>

    <template v-if="period.error === '' && problem === 'forbidden'">
      <EmptyState
        icon="lock"
        :title="t('accessReview.forbidden.title')"
        :description="t('accessReview.forbidden.description')"
        data-testid="review-forbidden"
      />
    </template>
    <p
      v-else-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-else-if="sections.length > 0">
      <div class="meta">
        <span class="pd-muted">
          {{ t('accessReview.generatedAt') }}
          <TimeCell :iso="generatedAt" />
        </span>
        <span class="exports">
          <v-btn
            variant="tonal"
            :href="exportUrl(scope, period, 'json')"
            download
            data-testid="export-json"
          >
            {{ t('accessReview.exportJson') }}
          </v-btn>
          <v-btn
            variant="tonal"
            :href="exportUrl(scope, period, 'csv')"
            download
            data-testid="export-csv"
          >
            {{ t('accessReview.exportCsv') }}
          </v-btn>
        </span>
      </div>
      <p
        v-if="stepUp"
        data-testid="review-stepup"
      >
        {{ t('accessReview.stepUp', { succeeded: stepUp.succeeded, failed: stepUp.failed }) }}
      </p>
      <v-expansion-panels
        :key="loadedFor"
        multiple
        variant="accordion"
        data-testid="review-sections"
      >
        <AccessReviewSection
          v-for="s in sections"
          :key="s.key"
          :section="s"
        />
      </v-expansion-panels>
    </template>
  </section>
</template>

<style scoped>
.period {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
  margin: 1rem 0 0.5rem;
}
.period :deep(.v-text-field) {
  max-width: 11rem;
}
.meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  align-items: center;
  justify-content: space-between;
  margin: 1rem 0;
}
.exports {
  display: flex;
  gap: 0.5rem;
}
</style>
