<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { AuditIntegrity, AuditManifest, AuditVerificationRun } from '../api/client'
import DataList from '../components/DataList.vue'
import EmptyState from '../components/EmptyState.vue'
import KpiStrip from '../components/KpiStrip.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import {
  getAuditIntegrity, integrityCells, listManifests, listVerificationRuns, manifestFilters, resultStatus, runFilters,
} from '../lib/auditIntegrity'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'

/**
 * Evidence integrity (plan M8b decision 32): which days are sealed, every chain verification run with its result
 * and problems, and the newest result per sealed day. Read-only, for organization administrators and auditors.
 */
const { t } = useI18n()
const problemText = useProblemText()
const summary = ref<AuditIntegrity | null>(null)
const problem = ref('')

onMounted(async () => {
  const s = await getAuditIntegrity()
  if (typeof s === 'string') problem.value = s
  else summary.value = s
})

const cells = computed(() => (summary.value ? integrityCells(summary.value, new Date()) : []))

const runColumns: ListColumn[] = [
  { key: 'started_at', title: 'auditIntegrity.runs.startedAt', sortable: true, role: 'meta' },
  { key: 'trigger', title: 'auditIntegrity.runs.trigger', role: 'meta' },
  { key: 'from_day', title: 'auditIntegrity.runs.range', sortable: true, role: 'primary', mono: true },
  { key: 'days', title: 'auditIntegrity.runs.days', role: 'meta', align: 'end', hideBelow: 'md' },
  { key: 'objects', title: 'auditIntegrity.runs.objects', role: 'meta', align: 'end', hideBelow: 'md' },
  { key: 'ok', title: 'auditIntegrity.runs.result', sortable: true, role: 'status' },
]

const manifestColumns: ListColumn[] = [
  { key: 'day', title: 'auditIntegrity.manifests.day', sortable: true, role: 'primary', mono: true },
  { key: 'sha256', title: 'auditIntegrity.manifests.sha256', role: 'meta', mono: true, hideBelow: 'sm' },
  { key: 'key_version', title: 'auditIntegrity.manifests.keyVersion', role: 'meta', align: 'end', hideBelow: 'md' },
  { key: 'last_verified_at', title: 'auditIntegrity.manifests.lastVerified', role: 'meta' },
  { key: 'last_verified_ok', title: 'auditIntegrity.runs.result', role: 'status' },
]

/** The first characters of a hash; the page shows the full value as the tooltip. */
function short(hash: string): string {
  return hash.slice(0, 12) + '…'
}
</script>

<template>
  <section class="page">
    <h1>{{ t('auditIntegrity.title') }}</h1>
    <div
      v-if="problem === 'forbidden'"
      data-testid="audit-integrity-forbidden"
    >
      <EmptyState
        icon="lock"
        :title="t('auditIntegrity.forbidden.title')"
        :description="t('auditIntegrity.forbidden.description')"
      />
    </div>
    <p
      v-else-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-else>
      <p class="pd-muted">
        {{ t('auditIntegrity.intro') }}
      </p>
      <div data-testid="audit-integrity-kpis">
        <KpiStrip
          v-if="summary"
          :cells="cells"
        />
      </div>

      <h2>{{ t('auditIntegrity.runs.title') }}</h2>
      <DataList
        :columns="runColumns"
        :fetch="listVerificationRuns"
        :filters="runFilters"
        searchable
        expandable
        query-prefix="runs"
        default-sort="-started_at"
        item-value="id"
        empty-icon="shield-check"
        empty-title="auditIntegrity.runs.empty.title"
        empty-description="auditIntegrity.runs.empty.description"
        data-testid="verification-runs"
      >
        <template #[`item.started_at`]="{ item }: { item: AuditVerificationRun }">
          <TimeCell :iso="item.started_at" />
        </template>
        <template #[`item.trigger`]="{ item }: { item: AuditVerificationRun }">
          {{ t('auditIntegrity.triggers.' + item.trigger) }}
        </template>
        <template #[`item.from_day`]="{ item }: { item: AuditVerificationRun }">
          <span class="mono">{{ item.from_day === item.to_day ? item.from_day : item.from_day + ' – ' + item.to_day }}</span>
        </template>
        <template #[`item.ok`]="{ item }: { item: AuditVerificationRun }">
          <StatusChip
            class="run-result"
            :status="resultStatus(item.ok).status"
            :label="t(resultStatus(item.ok).label)"
          />
        </template>
        <template #expanded="{ item }: { item: AuditVerificationRun }">
          <p
            v-if="item.problems.length === 0"
            class="pd-muted"
          >
            {{ t('auditIntegrity.runs.noProblems') }}
          </p>
          <ul
            v-else
            data-testid="run-problems"
          >
            <li
              v-for="(p, i) in item.problems"
              :key="i"
              class="mono"
            >
              {{ p }}
            </li>
          </ul>
        </template>
      </DataList>

      <h2>{{ t('auditIntegrity.manifests.title') }}</h2>
      <DataList
        :columns="manifestColumns"
        :fetch="listManifests"
        :filters="manifestFilters"
        searchable
        query-prefix="manifests"
        default-sort="-day"
        item-value="day"
        empty-icon="scroll-text"
        empty-title="auditIntegrity.manifests.empty.title"
        empty-description="auditIntegrity.manifests.empty.description"
        data-testid="audit-manifests"
      >
        <template #[`item.sha256`]="{ item }: { item: AuditManifest }">
          <span
            class="mono"
            :title="item.sha256"
          >{{ short(item.sha256) }}</span>
        </template>
        <template #[`item.last_verified_at`]="{ item }: { item: AuditManifest }">
          <TimeCell
            v-if="item.last_verified_at"
            :iso="item.last_verified_at"
          />
          <span
            v-else
            class="pd-muted"
          >–</span>
        </template>
        <template #[`item.last_verified_ok`]="{ item }: { item: AuditManifest }">
          <StatusChip
            class="manifest-result"
            :status="resultStatus(item.last_verified_ok).status"
            :label="t(resultStatus(item.last_verified_ok).label)"
          />
        </template>
      </DataList>
    </template>
  </section>
</template>
