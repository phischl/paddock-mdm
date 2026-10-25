<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { AgentRelease, AgentReleaseCheck, AgentReleaseSource, ComponentTarget } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import {
  agentReleaseFilters,
  checkAgentReleaseSource,
  getAgentReleaseSource,
  getComponentTargets,
  importAgentRelease,
  importableVersion,
  listAgentReleases,
  releaseTargetsExist,
  sourcePanelState,
} from '../lib/agentReleases'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { releaseStatus, rolloutStatus } from '../lib/status'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'

/** Step-up action of the import (ADR 0043 decision 7); the source is a singleton, so the target is fixed. */
const importAction = 'agent-release-import'
const stepUpTarget = 'source'

/** Problems after which the shown version may be stale, so the panel checks again (PDK-428). */
const recheckAfter = ['release_not_newer', 'step_up_failed']

const { t, te, locale } = useI18n()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const targets = ref<ComponentTarget[]>([])
const list = ref<{ reload: () => Promise<void> } | null>(null)
const source = ref<AgentReleaseSource | string | null>(null)
const check = ref<AgentReleaseCheck | null>(null)
const checking = ref(false)
const importing = ref(false)
const problem = ref('')
const imported = ref('')

const panel = computed(() => sourcePanelState(source.value, check.value))
const importVersion = computed(() => importableVersion(panel.value))
const busy = computed(() => checking.value || importing.value)

/** The problem text; codes whose generic text names another system get a release-specific one. */
function sourceProblemText(code: string): string {
  const key = 'agentReleases.source.problems.' + code
  return te(key) ? t(key) : problemText(code)
}

function resultText(c: AgentReleaseCheck): string {
  if (c.importable && c.latest) {
    return c.published_at
      ? t('agentReleases.source.available', { version: c.latest, at: formatDateTime(c.published_at, locale.value) })
      : t('agentReleases.source.availableUndated', { version: c.latest })
  }
  if (c.reason === 'not_newer') {
    return t('agentReleases.source.notNewer', { version: c.newest_stored ?? c.latest ?? '' })
  }
  return t('agentReleases.source.noneFound')
}

async function runCheck(keepProblem = false): Promise<void> {
  if (!keepProblem) problem.value = ''
  checking.value = true
  const res = await checkAgentReleaseSource()
  checking.value = false
  if (typeof res === 'string') {
    check.value = null
    problem.value = res
    return
  }
  check.value = res
}

async function onCheck(): Promise<void> {
  imported.value = ''
  await runCheck()
}

async function settleProblem(code: string): Promise<void> {
  problem.value = code
  if (recheckAfter.includes(code)) await runCheck(true)
}

async function runImport(version: string, stepUp: boolean): Promise<void> {
  problem.value = ''
  imported.value = ''
  importing.value = true
  const res = await importAgentRelease(version)
  importing.value = false
  if (res === stepUpRequired && stepUp) {
    startStepUp(importAction, stepUpTarget, { version })
    return
  }
  if (typeof res === 'string') {
    await settleProblem(res)
    return
  }
  imported.value = res.release.version
  check.value = null
  await list.value?.reload()
}

async function onImport(): Promise<void> {
  const version = importVersion.value
  if (!version || panel.value.kind !== 'checked') return
  const confirmed = await confirm({
    title: t('agentReleases.source.importTitle', { version }),
    message: t('agentReleases.source.importMessage', { version, repository: panel.value.repository }),
    confirmLabel: t('agentReleases.source.importConfirm', { version }),
    destructive: false,
  })
  if (!confirmed) return
  await runImport(version, true)
}

async function loadTargets(): Promise<void> {
  const res = await getComponentTargets()
  targets.value = typeof res === 'string' ? [] : res
}

onMounted(async () => {
  void loadTargets()
  source.value = await getAgentReleaseSource()
  const resumed = resumeStepUp<{ version: string }>(importAction, stepUpTarget)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    await settleProblem('step_up_failed')
    return
  }
  await runImport(resumed.payload.version, false)
})

const columns: ListColumn[] = [
  { key: 'version', title: 'agentReleases.version', sortable: true },
  { key: 'status', title: 'agentReleases.status', sortable: true },
  { key: 'rollout_status', title: 'agentReleases.rollout' },
  { key: 'artifact_count', title: 'agentReleases.artifacts' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
]
</script>

<template>
  <section class="page">
    <h1>{{ t('agentReleases.title') }}</h1>
    <p>{{ t('agentReleases.uploadHint') }}</p>
    <section
      v-if="panel.kind !== 'hidden'"
      class="pd-panel release-source"
      aria-labelledby="release-source-title"
      data-testid="release-source"
    >
      <header class="pd-panel-header">
        <h2
          id="release-source-title"
          class="pd-type-section"
        >
          {{ t('agentReleases.source.title') }}
        </h2>
      </header>
      <div class="pd-panel-body">
        <dl class="pd-facts">
          <div>
            <dt>{{ t('agentReleases.source.repository') }}</dt>
            <dd
              class="mono"
              data-testid="release-source-repository"
            >
              {{ panel.repository }}
            </dd>
          </div>
        </dl>
        <p
          v-if="panel.kind === 'checked'"
          class="release-source-text"
          data-testid="release-source-result"
        >
          {{ resultText(panel.check) }}
        </p>
        <p
          v-if="problem"
          class="form-error"
          role="alert"
          data-testid="release-source-problem"
        >
          {{ sourceProblemText(problem) }}
        </p>
        <v-alert
          v-if="imported"
          type="success"
          variant="tonal"
          class="release-source-text"
          data-testid="release-source-success"
        >
          {{ t('agentReleases.source.imported', { version: imported }) }}
          <RouterLink :to="{ name: 'agent-release', params: { version: imported } }">
            {{ t('agentReleases.source.openRelease', { version: imported }) }}
          </RouterLink>
        </v-alert>
        <p
          v-if="importing"
          class="pd-type-caption pd-muted"
          role="status"
        >
          {{ t('agentReleases.source.importing') }}
        </p>
        <div class="form-actions release-source-actions">
          <v-btn
            variant="tonal"
            :loading="checking"
            :disabled="busy"
            data-testid="release-source-check"
            @click="onCheck"
          >
            {{ t('agentReleases.source.check') }}
          </v-btn>
          <v-btn
            v-if="importVersion"
            color="primary"
            :loading="importing"
            :disabled="busy"
            data-testid="release-source-import"
            @click="onImport"
          >
            {{ t('agentReleases.source.import', { version: importVersion }) }}
          </v-btn>
        </div>
      </div>
    </section>
    <section
      class="pd-panel"
      aria-labelledby="rollout-targets-title"
      data-testid="rollout-targets"
    >
      <header class="pd-panel-header">
        <h2
          id="rollout-targets-title"
          class="pd-type-section"
        >
          {{ t('agentReleases.targets.title') }}
        </h2>
      </header>
      <div class="pd-panel-body">
        <dl class="pd-facts">
          <div
            v-for="target in targets"
            :key="target.component"
            :data-testid="'target-' + target.component"
          >
            <dt>{{ t('devices.components.names.' + target.component) }}</dt>
            <dd>
              <span class="mono">{{ target.version }}</span>
              <span class="pd-muted"> ({{ target.source }})</span>
            </dd>
          </div>
        </dl>
        <p
          v-if="!releaseTargetsExist(targets)"
          class="pd-muted"
          data-testid="rollout-targets-none"
        >
          {{ t('agentReleases.targets.none') }}
        </p>
        <p class="pd-type-caption pd-muted">
          {{ t('agentReleases.targets.himmelblauHint') }}
        </p>
        <p
          class="pd-type-caption pd-muted"
          data-testid="rollout-targets-hint"
        >
          {{ t('devices.components.targetHint') }}
        </p>
      </div>
    </section>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listAgentReleases"
      :filters="agentReleaseFilters"
      searchable
      default-sort="-created_at"
      item-value="version"
      empty-icon="rocket"
      empty-title="agentReleases.empty.title"
      empty-description="agentReleases.empty.description"
      data-testid="agent-release-list"
    >
      <template #[`item.version`]="{ item }: { item: AgentRelease }">
        <RouterLink :to="{ name: 'agent-release', params: { version: item.version } }">
          {{ item.version }}
        </RouterLink>
      </template>
      <template #[`item.status`]="{ item }: { item: AgentRelease }">
        <StatusChip
          :status="releaseStatus(item.status).status"
          :label="t(releaseStatus(item.status).label)"
        />
      </template>
      <template #[`item.rollout_status`]="{ item }: { item: AgentRelease }">
        <StatusChip
          v-if="item.rollout_status"
          :status="rolloutStatus(item.rollout_status).status"
          :label="t(rolloutStatus(item.rollout_status).label)"
        />
        <span
          v-else
          class="pd-muted"
        >{{ t('agentReleases.noRollout') }}</span>
      </template>
      <template #[`item.created_at`]="{ item }: { item: AgentRelease }">
        <TimeCell :iso="item.created_at" />
      </template>
    </DataList>
  </section>
</template>

<style scoped>
.release-source {
  margin-bottom: var(--pd-space-4);
}

.release-source-actions {
  margin-top: var(--pd-space-4);
}

/* A release version is one long token (a pre-release can exceed 35 characters), wider than the panel at 375 px:
   it breaks inside the token instead of running out of the panel (PDK-428 review). */
.release-source-text {
  overflow-wrap: anywhere;
}

/* Vuetify keeps a button label on one line at a fixed height; with the version in the import label the button grew
   past the panel's left edge at 375 px (the actions align right) and was cut off, so the label wraps instead. */
.release-source-actions .v-btn {
  max-width: 100%;
  height: auto;
  padding-block: var(--pd-space-2);
}

.release-source-actions :deep(.v-btn__content) {
  white-space: normal;
  overflow-wrap: anywhere;
}
</style>
