<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import AccessReviewSection from '../components/AccessReviewSection.vue'
import EmptyState from '../components/EmptyState.vue'
import KpiStrip from '../components/KpiStrip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { ReviewSection } from '../lib/accessReview'
import { allGroups } from '../lib/devices'
import { getPatchCompliance, patchCells, patchExportUrl, patchSections, type PatchComplianceReport } from '../lib/patchCompliance'
import { useProblemText } from '../lib/problems'

/**
 * The patch compliance report (plan M13c decision 18 and amendment 2026-11-14): the state at its generation, with no
 * period, for all devices or one device group (kept in the route query); the cards of the summary, one expandable
 * table per section and the exports.
 */
const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const problemText = useProblemText()

const group = computed(() => (typeof route.query.group === 'string' ? route.query.group : ''))
const report = ref<PatchComplianceReport | null>(null)
const sections = ref<ReviewSection[]>([])
const groups = ref<{ id: string; name: string }[]>([])
const problem = ref('')
let request = 0

const cells = computed(() => (report.value ? patchCells(report.value) : []))
const groupItems = computed(() => [
  { title: t('patchCompliance.allGroups'), value: '' },
  ...groups.value.map((g) => ({ title: g.name, value: g.id })),
])

async function load(): Promise<void> {
  const current = ++request
  problem.value = ''
  report.value = null
  sections.value = []
  const result = await getPatchCompliance(group.value)
  if (current !== request) return
  if (typeof result === 'string') {
    problem.value = result
    return
  }
  report.value = result
  sections.value = patchSections(result, (s) => t('inventory.severities.' + s))
}

watch(group, () => void load(), { immediate: true })

onMounted(async () => {
  groups.value = await allGroups()
})

/** A new group filter replaces the query, so the section lists start over. */
function chooseGroup(value: string | null): void {
  void router.push({ query: value ? { group: value } : {} })
}
</script>

<template>
  <section class="page">
    <h1>{{ t('patchCompliance.title') }}</h1>
    <p class="pd-muted">
      {{ t('patchCompliance.intro') }}
    </p>

    <div class="filters">
      <v-autocomplete
        :model-value="group"
        :items="groupItems"
        :label="t('patchCompliance.group')"
        class="group-filter"
        hide-details
        data-testid="patch-group"
        @update:model-value="chooseGroup"
      />
    </div>

    <EmptyState
      v-if="problem === 'forbidden'"
      icon="lock"
      :title="t('patchCompliance.forbidden.title')"
      :description="t('patchCompliance.forbidden.description')"
      data-testid="patch-forbidden"
    />
    <p
      v-else-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-else-if="report">
      <div class="meta">
        <span
          class="pd-muted"
          data-testid="patch-state-at"
        >
          {{ t('patchCompliance.stateAt') }}
          <TimeCell :iso="report.generated_at" />
        </span>
        <span class="exports">
          <v-btn
            variant="tonal"
            :href="patchExportUrl(group, 'json')"
            download
            data-testid="export-json"
          >
            {{ t('accessReview.exportJson') }}
          </v-btn>
          <v-btn
            variant="tonal"
            :href="patchExportUrl(group, 'csv')"
            download
            data-testid="export-csv"
          >
            {{ t('accessReview.exportCsv') }}
          </v-btn>
        </span>
      </div>
      <KpiStrip :cells="cells" />
      <EmptyState
        v-if="report.summary.devices === 0"
        icon="package-search"
        :title="t('patchCompliance.empty.title')"
        :description="t('patchCompliance.empty.description')"
        data-testid="patch-empty"
      />
      <p
        v-if="report.devices_total > report.devices.length"
        class="form-error"
        role="status"
        data-testid="patch-cap"
      >
        {{ t('patchCompliance.capNotice', { shown: report.devices.length, total: report.devices_total }) }}
      </p>
      <v-expansion-panels
        :key="report.generated_at"
        multiple
        variant="accordion"
        class="sections"
        data-testid="patch-sections"
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
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
  margin: 1rem 0 0.5rem;
}
.group-filter {
  min-width: 12rem;
  max-width: 20rem;
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
.sections {
  margin-top: 1rem;
}
</style>
