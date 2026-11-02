<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import ChangeSetPlan from '../components/ChangeSetPlan.vue'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import type { ConfigRolloutDetail, ConfigRolloutDevice } from '../api/client'
import { usePending } from '../composables/usePending'
import { useConfirm, type ConfirmOptions } from '../composables/useConfirm'
import {
  getConfigRollout, rolloutActionsFor, rolloutDeviceFilters, rolloutDevicesFetcher, rolloutOpen, rolloutPercent, runRolloutAction,
  type RolloutAction,
} from '../lib/configRollouts'
import { allGroups } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { configRolloutStatus } from '../lib/status'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const problemText = useProblemText()
const confirm = useConfirm()
const { pending, run } = usePending()
const detail = ref<ConfigRolloutDetail | null>(null)
const problem = ref('')
const canaryName = ref('')
const list = ref<{ reload: () => Promise<void> } | null>(null)
const id = computed(() => String(route.params.id))
const fetchDevices = computed(() => rolloutDevicesFetcher(id.value))
const rollout = computed(() => detail.value?.rollout ?? null)
const actions = computed<RolloutAction[]>(() => (session.canWrite && rollout.value ? rolloutActionsFor(rollout.value) : []))

const columns: ListColumn[] = [
  { key: 'hostname', title: 'configRollouts.devices.hostname', sortable: true },
  { key: 'in_wave', title: 'configRollouts.devices.inWave', sortable: true },
  { key: 'bundle_version', title: 'configRollouts.devices.bundle' },
  { key: 'report_outcome', title: 'configRollouts.devices.outcome', sortable: true },
  { key: 'failed_resource_ids', title: 'configRollouts.devices.failed' },
]

async function load(): Promise<void> {
  const d = await getConfigRollout(id.value)
  if (typeof d === 'string') {
    problem.value = d
    return
  }
  detail.value = d
  const groupID = d.rollout.canary_device_group_id
  if (groupID) canaryName.value = (await allGroups()).find((g) => g.id === groupID)?.name ?? groupID
}

onMounted(load)

/** The modal of an action: halt asks for the reason, complete says that every device receives the change. */
function confirmation(action: RolloutAction): ConfirmOptions {
  return {
    title: t('configRollouts.actions.' + action + '.title'),
    message: t('configRollouts.actions.' + action + '.confirm'),
    confirmLabel: t('configRollouts.actions.' + action + '.label'),
    destructive: action === 'halt' || action === 'complete',
  }
}

async function act(action: RolloutAction): Promise<void> {
  problem.value = ''
  let reason = ''
  if (action === 'halt') {
    const answer = await confirm({
      ...confirmation(action), reason: { label: t('configRollouts.actions.halt.reason'), required: true, minLength: 2, maxLength: 500 },
    })
    if (!answer) return
    reason = answer.reason
  } else if (!(await confirm(confirmation(action)))) {
    return
  }
  const res = await runRolloutAction(id.value, action, reason)
  if (typeof res === 'string') problem.value = res
  await load()
  await list.value?.reload()
}

/** The revert dialog of the change sets page shows the inverse plan and confirms it (plan M11 decision 22). */
function revert(): void {
  if (!detail.value) return
  void router.push({ name: 'change-sets', query: { revert: detail.value.change_set.id } })
}

type WaveState = 'done' | 'current' | 'upcoming'

/** Where a wave stands: the ones before the current are reached; a completed rollout reached them all. */
function waveState(index: number): WaveState {
  const r = rollout.value
  if (!r) return 'upcoming'
  if (r.status === 'completed' || index < r.current_wave_index) return 'done'
  return index === r.current_wave_index ? 'current' : 'upcoming'
}

function outcomeStatus(o: string): 'ok' | 'critical' | 'neutral' {
  if (o === 'applied') return 'ok'
  return o === 'rejected' ? 'critical' : 'neutral'
}
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'config-rollouts' }">
        {{ t('configRollouts.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="detail && rollout">
      <div class="page-header">
        <h1>{{ t('configRollouts.heading') }}</h1>
        <div class="row-actions">
          <v-btn
            v-for="action in actions"
            :key="action"
            :color="action === 'halt' ? 'error' : 'primary'"
            :loading="pending"
            :disabled="pending"
            :data-testid="'config-rollout-' + action"
            @click="run(() => act(action))"
          >
            {{ t('configRollouts.actions.' + action + '.label') }}
          </v-btn>
          <v-btn
            v-if="session.canWrite && rolloutOpen(rollout)"
            variant="tonal"
            color="error"
            data-testid="config-rollout-revert"
            @click="revert"
          >
            {{ t('configRollouts.actions.revert.label') }}
          </v-btn>
        </div>
      </div>

      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('configRollouts.status') }}
            </th>
            <td>
              <StatusChip
                :status="configRolloutStatus(rollout.status).status"
                :label="t(configRolloutStatus(rollout.status).label)"
                data-testid="config-rollout-status"
              />
            </td>
          </tr>
          <tr v-if="rollout.halted_reason">
            <th scope="row">
              {{ t('configRollouts.haltedReason') }}
            </th>
            <td data-testid="config-rollout-halted-reason">
              {{ rollout.halted_reason }}
            </td>
          </tr>
          <tr v-if="rollout.ended_at">
            <th scope="row">
              {{ t('configRollouts.endedAt') }}
            </th>
            <td>{{ formatDateTime(rollout.ended_at, locale) }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('configRollouts.startedBy') }}
            </th>
            <td>{{ t('configRollouts.startedFacts', { by: rollout.started_by, at: formatDateTime(rollout.started_at, locale) }) }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('configRollouts.wave') }}
            </th>
            <td data-testid="config-rollout-wave">
              {{ t('configRollouts.waveShort', { wave: rollout.current_wave_index + 1, waves: rollout.waves.length, percent: rolloutPercent(rollout) }) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('configRollouts.thresholds') }}
            </th>
            <td>
              {{ t('configRollouts.thresholdFacts', {
                minutes: rollout.min_wave_minutes, percent: rollout.failure_threshold_percent, min: rollout.failure_threshold_min,
              }) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('configRollouts.counts') }}
            </th>
            <td data-testid="config-rollout-counts">
              {{ t('configRollouts.countFacts', rollout.counts) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('configRollouts.changeSet') }}
            </th>
            <td>
              <RouterLink :to="{ name: 'change-sets' }">
                {{ t('configRollouts.changeSetLink', { at: formatDateTime(detail.change_set.applied_at, locale) }) }}
              </RouterLink>
            </td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('configRollouts.waves') }}</h2>
      <ol
        class="wave-strip"
        :aria-label="t('configRollouts.waves')"
        data-testid="config-rollout-waves"
      >
        <li
          v-for="(percent, i) in rollout.waves"
          :key="i"
          class="wave-step"
          :class="'wave-step--' + waveState(i)"
          :aria-current="waveState(i) === 'current' ? 'step' : undefined"
          :data-testid="'wave-' + (i + 1)"
        >
          <span class="wave-percent">{{ t('configRollouts.wavePercent', { percent }) }}</span>
          <span class="wave-state">{{ t('configRollouts.waveStates.' + waveState(i)) }}</span>
        </li>
      </ol>
      <p
        v-if="rollout.canary_device_group_id"
        class="pd-type-caption pd-muted"
        data-testid="config-rollout-canary"
      >
        {{ t('configRollouts.canary', { group: canaryName }) }}
      </p>

      <h2>{{ t('configRollouts.plan') }}</h2>
      <ChangeSetPlan :plan="detail.change_set.plan" />

      <h2>{{ t('configRollouts.devices.title') }}</h2>
      <DataList
        ref="list"
        :columns="columns"
        :fetch="fetchDevices"
        :filters="rolloutDeviceFilters"
        searchable
        default-sort="hostname"
        item-value="device_id"
        empty-icon="laptop"
        empty-title="configRollouts.devices.empty.title"
        empty-description="configRollouts.devices.empty.description"
        data-testid="config-rollout-devices"
      >
        <template #[`item.hostname`]="{ item }: { item: ConfigRolloutDevice }">
          <RouterLink :to="{ name: 'device', params: { id: item.device_id } }">
            {{ item.hostname }}
          </RouterLink>
        </template>
        <template #[`item.in_wave`]="{ item }: { item: ConfigRolloutDevice }">
          {{ item.in_wave ? t('configRollouts.devices.inWaveYes') : t('configRollouts.devices.inWaveNo') }}
        </template>
        <template #[`item.bundle_version`]="{ item }: { item: ConfigRolloutDevice }">
          {{ item.bundle_version ?? '–' }}
          <span v-if="item.bundle_version !== null && item.carries_rollout">{{ t('configRollouts.devices.carries') }}</span>
        </template>
        <template #[`item.report_outcome`]="{ item }: { item: ConfigRolloutDevice }">
          <StatusChip
            :status="outcomeStatus(item.report_outcome)"
            :label="t('configRollouts.devices.outcomes.' + item.report_outcome)"
          />
        </template>
        <template #[`item.failed_resource_ids`]="{ item }: { item: ConfigRolloutDevice }">
          {{ item.failed_resource_ids.join(', ') || '–' }}
        </template>
      </DataList>
    </template>
  </section>
</template>
