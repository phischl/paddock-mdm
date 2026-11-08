<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import BackupKeyDialog, { type KeyDialogKey } from '../components/BackupKeyDialog.vue'
import BackupRestorePlanDialog from '../components/BackupRestorePlanDialog.vue'
import BackupTargetForm from '../components/BackupTargetForm.vue'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import { useConfirm } from '../composables/useConfirm'
import { useFocusReturn } from '../composables/useFocusReturn'
import { usePending } from '../composables/usePending'
import {
  abandonRestorePlan, attemptsLeft, backupKinds, cancelRestorePlan, confirmKey, createRestorePlan, createTarget, deleteTarget, discardKey, generateKey, getTarget, hasSecrets, hostStateStatus,
  isProblem, keyStatus, kindStatus, loadOverview, needsHostStep, planFilters, planLister, planStateStatus, requestRun, runFilters,
  runLister, saveSchedule, scheduleErrors,
  scheduleFields, scheduleOf, scheduleRanges, setTargetEnabled, stepUpTarget, targetFilters, targetLister, testPollIntervalMs,
  testPollTimeoutMs, testStatus, testTarget, updateTarget, withoutSecrets, type BackupKey, type BackupOverview, type BackupProblem,
  type BackupRestorePlan, type BackupRun, type BackupScheduleUpdate, type BackupTarget, type PlanInput, type TargetInput,
} from '../lib/backup'
import { formatDateTime, formatGB } from '../lib/format'
import type { ListColumn, ListParams, Page } from '../lib/listQuery'
import { pollUntil } from '../lib/notifications'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'

/**
 * Platform backup (plan M15 §3.8, ADR 0046): the state of every target and kind, targets, the key with its
 * confirmation, the schedule and the history. Every change needs a step-up; the refused action is repeated once when
 * the browser comes back. The key text lives in this component's memory only while its dialog is open and is dropped
 * when the dialog ends or the page is left; credentials never wait in the browser's storage, so a step-up that
 * interrupts a typed credential asks for it again.
 */
type Operation =
  | { op: 'generate' }
  | { op: 'resume-confirm' }
  | { op: 'discard'; id: string }
  | { op: 'run' }
  | { op: 'schedule'; body: BackupScheduleUpdate }
  | { op: 'create'; input: TargetInput; hadSecrets: boolean }
  | { op: 'update'; id: string; input: TargetInput; hadSecrets: boolean }
  | { op: 'delete'; id: string; name: string }
  | { op: 'test'; id: string; name: string }
  | { op: 'toggle'; id: string; enable: boolean }
  | { op: 'plan'; input: PlanInput }
  | { op: 'cancel-plan'; id: string }
  | { op: 'abandon-plan'; id: string; confirmation: string }

const tabs = ['overview', 'targets', 'key', 'schedule', 'history', 'restore'] as const
type Tab = (typeof tabs)[number]
const stepUpAction = 'backup'

const { t, locale } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const confirm = useConfirm()
const route = useRoute()
const router = useRouter()
const focusReturn = useFocusReturn()
const targetList = ref<{ reload: () => Promise<void> } | null>(null)
const runList = ref<{ reload: () => Promise<void> } | null>(null)
const retiredList = ref<{ reload: () => Promise<void> } | null>(null)
const planList = ref<{ reload: () => Promise<void> } | null>(null)

const tab = computed<Tab>(() => (tabs as readonly string[]).includes(route.query.tab as string) ? (route.query.tab as Tab) : 'overview')
const overview = ref<BackupOverview | null>(null)
const pageProblem = ref('')
const saved = ref('')
const hostStep = ref(false)
const testing = ref<{ name: string; phase: 'waiting' | 'ok' | 'error' | 'timeout'; error: string } | null>(null)
let cancelled = false

const targetDialog = ref<{ editing: BackupTarget | null; restored: TargetInput | null } | null>(null)
const targetKey = ref(0)
const targetProblem = ref<BackupProblem | null>(null)
const reenterCredentials = ref(false)

// The restore plan dialog: plan is null while the form is asked for, then the approved plan with its host command.
const planDialog = ref<{ plan: BackupRestorePlan | null } | null>(null)
const planProblem = ref('')

// The key dialog's state; keyInfo.text is the only place the key text exists in the browser.
const keyDialog = ref<{ step: 1 | 2 | 3 } | null>(null)
const keyInfo = ref<KeyDialogKey | null>(null)
const keyAttempts = ref<number | null>(null)
const keyProblem = ref('')

const schedule = reactive<BackupScheduleUpdate>({
  full_interval_hours: 24, openbao_interval_hours: 6, fleet_interval_hours: 24, escrow_interval_hours: 1,
  retention_full: 14, openbao_keep_days: 30, fleet_keep_days: 30,
})
const scheduleTouched = ref(false)
const invalidSchedule = computed(() => (scheduleTouched.value ? scheduleErrors(schedule) : []))

const planColumns: ListColumn[] = [
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  { key: 'kind', title: 'backup.restore.kind' },
  { key: 'state', title: 'backup.restore.state', sortable: true, role: 'status' },
  { key: 'source', title: 'backup.restore.source_column' },
  { key: 'at', title: 'backup.restore.pointInTime' },
  { key: 'components', title: 'backup.restore.components_column' },
  { key: 'created_by', title: 'backup.restore.createdBy' },
  { key: 'actions', title: 'common.actions' },
]
const targetColumns: ListColumn[] = [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'type', title: 'backup.targets.type', sortable: true },
  { key: 'enabled', title: 'backup.targets.enabled' },
  { key: 'host_state', title: 'backup.targets.hostState', role: 'status' },
  { key: 'test', title: 'backup.targets.test' },
  { key: 'actions', title: 'common.actions' },
]
const runColumns: ListColumn[] = [
  { key: 'started_at', title: 'backup.runs.startedAt', sortable: true },
  { key: 'kind', title: 'backup.runs.kind', sortable: true },
  { key: 'outcome', title: 'backup.runs.outcome', sortable: true, role: 'status' },
  { key: 'bytes', title: 'backup.runs.size' },
  { key: 'targets', title: 'backup.runs.targets' },
]
const retiredColumns: ListColumn[] = [
  { key: 'fingerprint', title: 'backup.key.fingerprintColumn', mono: true },
  { key: 'created_at', title: 'common.createdAt' },
  { key: 'retired_at', title: 'backup.key.retiredAt' },
]
const fetchTargets = targetLister()
const fetchRuns = runLister()
const fetchPlans = planLister()
// The retired keys come with the key state; the list contract is served from memory.
async function fetchRetired(p: ListParams): Promise<Page<BackupKey>> {
  const all = overview.value?.key.retired ?? []
  const start = (p.page - 1) * p.page_size
  return { items: all.slice(start, start + p.page_size), page: p.page, page_size: p.page_size, total: all.length, total_capped: false, sort: p.sort }
}

async function refresh(): Promise<void> {
  const res = await loadOverview()
  if (isProblem(res)) {
    pageProblem.value = res.code
    return
  }
  overview.value = res
  Object.assign(schedule, scheduleOf(res.schedule))
  void retiredList.value?.reload()
}

onMounted(async () => {
  await refresh()
  const resumed = resumeStepUp<Operation>(stepUpAction, stepUpTarget)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    pageProblem.value = 'step_up_failed'
    return
  }
  const operation = resumed.payload
  if ((operation.op === 'create' || operation.op === 'update') && operation.hadSecrets) {
    reenterCredentials.value = true
    targetProblem.value = null
    let editing: BackupTarget | null = null
    if (operation.op === 'update') {
      const current = await getTarget(operation.id)
      if (isProblem(current)) {
        pageProblem.value = current.code
        return
      }
      editing = current
    }
    targetKey.value++
    targetDialog.value = { editing, restored: operation.input }
    return
  }
  await execute(operation, false)
})
onBeforeUnmount(() => {
  cancelled = true
  dropKey()
})

function setTab(value: unknown): void {
  const next = (tabs as readonly string[]).includes(value as string) ? (value as Tab) : 'overview'
  void router.replace({ query: next === 'overview' ? {} : { tab: next } })
}

function dropKey(): void {
  keyInfo.value = null
  keyDialog.value = null
  keyAttempts.value = null
  keyProblem.value = ''
}

function keyOfPending(): KeyDialogKey | null {
  const p = overview.value?.key.pending
  if (!p?.positions) return null
  return { id: p.key_id, text: null, fingerprint: p.fingerprint, positions: p.positions, downloadName: '' }
}

function openKeyStart(event?: Event): void {
  focusReturn.remember(event)
  keyProblem.value = ''
  keyAttempts.value = null
  keyDialog.value = { step: 1 }
}

function openKeyConfirm(event?: Event): void {
  focusReturn.remember(event)
  const pendingKey = keyOfPending()
  if (!pendingKey) return
  keyProblem.value = ''
  keyAttempts.value = null
  keyInfo.value = pendingKey
  keyDialog.value = { step: 3 }
}

function cancelKeyStart(): void {
  dropKey()
  focusReturn.restore()
}

/** Sends the operation; step_up_required starts the step-up once and the page repeats the operation on return. */
async function execute(operation: Operation, stepUp: boolean): Promise<void> {
  saved.value = ''
  pageProblem.value = ''
  const answer = await perform(operation)
  if (answer === null) return
  if (answer.code === stepUpRequired && stepUp) {
    const payload = operation.op === 'create' || operation.op === 'update'
      ? { ...operation, input: withoutSecrets(operation.input), hadSecrets: hasSecrets(operation.input) }
      : operation
    startStepUp(stepUpAction, stepUpTarget, payload)
    return
  }
  if (operation.op === 'create' || operation.op === 'update') targetProblem.value = answer
  else if (operation.op === 'generate' || operation.op === 'discard') keyProblem.value = problemText(answer.code)
  else if (operation.op === 'plan' && planDialog.value) planProblem.value = problemText(answer.code)
  else if (operation.op === 'toggle' && answer.code === 'invalid_state') pageProblem.value = 'backup_target_state_unchanged'
  else pageProblem.value = answer.code
}

/** Performs one operation; null on success (the page state is updated), otherwise the problem. */
async function perform(operation: Operation): Promise<BackupProblem | null> {
  switch (operation.op) {
    case 'generate': {
      const res = await generateKey()
      if (isProblem(res)) return res
      keyInfo.value = { id: res.key_id, text: res.key, fingerprint: res.fingerprint, positions: res.positions, downloadName: res.download_name }
      keyProblem.value = ''
      keyDialog.value = { step: 2 }
      return null
    }
    case 'resume-confirm': {
      await refresh()
      openKeyConfirm()
      return null
    }
    case 'discard': {
      const res = await discardKey(operation.id)
      if (isProblem(res)) return res
      dropKey()
      saved.value = t('backup.key.discarded')
      focusReturn.restore()
      await refresh()
      return null
    }
    case 'run': {
      const res = await requestRun()
      if (res) return res
      saved.value = t('backup.run.requested')
      await refresh()
      void runList.value?.reload()
      return null
    }
    case 'schedule': {
      const res = await saveSchedule(operation.body)
      if (isProblem(res)) return res
      saved.value = t('backup.schedule.saved')
      await refresh()
      return null
    }
    case 'create': {
      const res = await createTarget(operation.input)
      if (isProblem(res)) return res
      return savedTarget(res, 'backup.targets.saved')
    }
    case 'update': {
      const res = await updateTarget(operation.id, operation.input)
      if (isProblem(res)) return res
      return savedTarget(res, 'backup.targets.saved')
    }
    case 'delete': {
      const res = await deleteTarget(operation.id)
      if (res) return res
      saved.value = t('backup.targets.deleted', { name: operation.name })
      focusReturn.restore(() => document.querySelector<HTMLElement>('[data-testid="backup-target-list"]'))
      await reloadTargets()
      return null
    }
    case 'plan': {
      const res = await createRestorePlan(operation.input)
      if (isProblem(res)) return res
      planProblem.value = ''
      planDialog.value = { plan: res }
      saved.value = t('backup.restore.created')
      void planList.value?.reload()
      return null
    }
    case 'cancel-plan': {
      const res = await cancelRestorePlan(operation.id)
      if (isProblem(res)) return res
      saved.value = t('backup.restore.cancelled')
      await planList.value?.reload()
      return null
    }
    case 'abandon-plan': {
      const res = await abandonRestorePlan(operation.id, operation.confirmation)
      if (isProblem(res)) return res
      saved.value = t('backup.restore.abandoned')
      await planList.value?.reload()
      return null
    }
    case 'test':
      return startTest(operation)
    case 'toggle': {
      const res = await setTargetEnabled(operation.id, operation.enable)
      if (isProblem(res)) return res
      saved.value = t(operation.enable ? 'backup.targets.enabledDone' : 'backup.targets.disabledDone', { name: res.name })
      await reloadTargets()
      return null
    }
  }
}

function savedTarget(target: BackupTarget, message: string): null {
  targetDialog.value = null
  focusReturn.restore()
  saved.value = t(message)
  hostStep.value = needsHostStep(target.type)
  void reloadTargets()
  return null
}

async function reloadTargets(): Promise<void> {
  await Promise.all([targetList.value?.reload(), refresh()])
}

async function startTest(operation: { id: string; name: string }): Promise<BackupProblem | null> {
  const before = await getTarget(operation.id)
  const baseline = isProblem(before) ? null : before.last_test_at
  const refused = await testTarget(operation.id)
  if (isProblem(refused)) return refused
  testing.value = { name: operation.name, phase: 'waiting', error: '' }
  void targetList.value?.reload()
  void watchTest(operation, baseline)
  return null
}

// Polled outside run(): the page's actions stay usable while the host works for up to a minute.
async function watchTest(operation: { id: string; name: string }, baseline: string | null): Promise<void> {
  const outcome = await pollUntil(async () => {
    const d = await getTarget(operation.id)
    if (isProblem(d)) return { ok: false, error: d.code }
    return !d.test_requested_at && d.last_test_at !== baseline ? { ok: d.last_test_ok === true, error: d.last_test_error ?? '' } : null
  }, () => cancelled, testPollIntervalMs, testPollTimeoutMs)
  testing.value = outcome === null
    ? { name: operation.name, phase: 'timeout', error: '' }
    : { name: operation.name, phase: outcome.ok ? 'ok' : 'error', error: outcome.error }
  void reloadTargets()
}

function openCreate(event?: Event): void {
  focusReturn.remember(event)
  targetProblem.value = null
  reenterCredentials.value = false
  targetKey.value++
  targetDialog.value = { editing: null, restored: null }
}

function openEdit(target: BackupTarget, event?: Event): void {
  focusReturn.remember(event)
  targetProblem.value = null
  reenterCredentials.value = false
  targetKey.value++
  targetDialog.value = { editing: target, restored: null }
}

function closeTargetDialog(): void {
  targetDialog.value = null
  focusReturn.restore(() => document.querySelector<HTMLElement>('[data-testid="backup-target-list"]'))
}

async function submitTarget(input: TargetInput): Promise<void> {
  targetProblem.value = null
  const editing = targetDialog.value?.editing ?? null
  await execute(editing ? { op: 'update', id: editing.id, input, hadSecrets: false } : { op: 'create', input, hadSecrets: false }, true)
}

async function onDelete(target: BackupTarget, event?: Event): Promise<void> {
  focusReturn.remember(event)
  const confirmed = await confirm({
    title: t('backup.targets.deleteTitle'),
    message: t('backup.targets.deleteConfirm', { name: target.name }),
    confirmLabel: t('common.delete'),
    destructive: true,
    requireTypedText: target.name,
  })
  if (!confirmed) return
  await run(() => execute({ op: 'delete', id: target.id, name: target.name }, true))
}

async function onToggle(target: BackupTarget, event?: Event): Promise<void> {
  focusReturn.remember(event)
  if (target.enabled) {
    const confirmed = await confirm({
      title: t('backup.targets.disableTitle'),
      message: t('backup.targets.disableConfirm', { name: target.name }),
      confirmLabel: t('backup.targets.disable'),
      destructive: true,
    })
    if (!confirmed) return
  }
  await run(() => execute({ op: 'toggle', id: target.id, enable: !target.enabled }, true))
}

async function onTest(target: BackupTarget, event?: Event): Promise<void> {
  focusReturn.remember(event)
  await run(() => execute({ op: 'test', id: target.id, name: target.name }, true))
}

async function onRun(event?: Event): Promise<void> {
  focusReturn.remember(event)
  const confirmed = await confirm({
    title: t('backup.run.title'),
    message: t('backup.run.confirm'),
    confirmLabel: t('backup.run.now'),
  })
  if (!confirmed) return
  await run(() => execute({ op: 'run' }, true))
}

function openPlan(event?: Event): void {
  focusReturn.remember(event)
  planProblem.value = ''
  planDialog.value = { plan: null }
}

function showPlan(plan: BackupRestorePlan, event?: Event): void {
  focusReturn.remember(event)
  planDialog.value = { plan }
}

function closePlanDialog(): void {
  planDialog.value = null
  planProblem.value = ''
  focusReturn.restore(() => document.querySelector<HTMLElement>('[data-testid="backup-plan-list"]'))
}

async function onCancelPlan(plan: BackupRestorePlan, event?: Event): Promise<void> {
  focusReturn.remember(event)
  const confirmed = await confirm({
    title: t('backup.restore.cancelTitle'),
    message: t('backup.restore.cancelConfirm'),
    confirmLabel: t('backup.restore.cancelAction'),
    destructive: true,
  })
  if (!confirmed) return
  await run(() => execute({ op: 'cancel-plan', id: plan.id }, true))
}

async function onAbandonPlan(plan: BackupRestorePlan, event?: Event): Promise<void> {
  focusReturn.remember(event)
  const confirmed = await confirm({
    title: t('backup.restore.abandonTitle'),
    message: t('backup.restore.abandonConfirm'),
    confirmLabel: t('backup.restore.abandonAction'),
    destructive: true,
    requireTypedText: 'abandon',
  })
  if (!confirmed) return
  await run(() => execute({ op: 'abandon-plan', id: plan.id, confirmation: 'abandon' }, true))
}

async function onGenerate(): Promise<void> {
  await run(() => execute({ op: 'generate' }, true))
}

async function onKeyConfirm(answer: string): Promise<void> {
  const k = keyInfo.value
  if (!k) return
  await run(async () => {
    keyProblem.value = ''
    const res = await confirmKey(k.id, answer)
    if (!isProblem(res)) {
      dropKey()
      saved.value = t('backup.key.confirmed')
      focusReturn.restore()
      await refresh()
      return
    }
    if (res.code === stepUpRequired) {
      startStepUp(stepUpAction, stepUpTarget, { op: 'resume-confirm' } satisfies Operation)
      return
    }
    if (res.code === 'backup_key_mismatch') {
      const left = attemptsLeft(res.detail)
      if (left === null) {
        dropKey()
        pageProblem.value = 'backup_key_discarded_after_mismatches'
        await refresh()
        return
      }
      keyAttempts.value = left
      return
    }
    keyProblem.value = problemText(res.code)
  })
}

async function onKeyDiscard(): Promise<void> {
  const k = keyInfo.value
  if (!k) return
  const confirmed = await confirm({
    title: t('backup.key.discardTitle'),
    message: t('backup.key.discardConfirm'),
    confirmLabel: t('backup.key.discardAction'),
    destructive: true,
  })
  if (!confirmed) return
  await run(() => execute({ op: 'discard', id: k.id }, true))
}

async function onSchedule(): Promise<void> {
  scheduleTouched.value = true
  if (scheduleErrors(schedule).length > 0) return
  await run(() => execute({ op: 'schedule', body: { ...schedule } }, true))
}

function planSource(plan: BackupRestorePlan): string {
  if (plan.source === 'set') return t('backup.restore.sourceSet')
  if (plan.source === 'repo') return t('backup.restore.sourceRepo')
  return plan.source_target_name ?? t('backup.restore.sourceTargetGone')
}

function sizeText(bytes: number | null | undefined): string {
  return bytes ? (formatGB(bytes, locale.value) ?? '') : ''
}

const keyBanner = computed(() => (overview.value ? keyStatus(overview.value.key) : null))
const dialogTitle = computed(() => (targetDialog.value?.editing ? t('backup.targets.editTitle') : t('backup.targets.createTitle')))
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('backup.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('backup.summary') }}
    </p>
    <p
      v-if="pageProblem"
      class="form-error"
      role="alert"
      data-testid="backup-page-problem"
    >
      {{ problemText(pageProblem) }}
    </p>
    <p
      v-if="saved"
      role="status"
      data-testid="backup-saved"
    >
      {{ saved }}
    </p>
    <v-alert
      v-if="hostStep"
      type="info"
      variant="tonal"
      class="conflict"
      closable
      data-testid="backup-host-step"
      @click:close="hostStep = false"
    >
      {{ t('backup.targets.hostStep', { apply: './paddock backup-target apply', up: './paddock up' }) }}
    </v-alert>
    <v-alert
      v-if="testing"
      :type="testing.phase === 'ok' ? 'success' : testing.phase === 'waiting' ? 'info' : 'warning'"
      variant="tonal"
      class="conflict"
      role="status"
      closable
      data-testid="backup-test-result"
      @click:close="testing = null"
    >
      <template v-if="testing.phase === 'waiting'">
        {{ t('backup.targets.testWaiting', { name: testing.name }) }}
      </template>
      <template v-else-if="testing.phase === 'ok'">
        {{ t('backup.targets.testOk', { name: testing.name }) }}
      </template>
      <template v-else-if="testing.phase === 'error'">
        {{ t('backup.targets.testError', { name: testing.name, error: testing.error || t('backup.targets.testUnknown') }) }}
      </template>
      <template v-else>
        {{ t('backup.targets.testTimeout', { name: testing.name }) }}
      </template>
    </v-alert>

    <v-tabs
      :model-value="tab"
      data-testid="backup-tabs"
      @update:model-value="setTab"
    >
      <v-tab
        v-for="name in tabs"
        :key="name"
        :value="name"
        :data-testid="'backup-tab-' + name"
      >
        {{ t('backup.tabs.' + name) }}
      </v-tab>
    </v-tabs>

    <div
      v-if="tab === 'overview'"
      role="tabpanel"
      data-testid="backup-panel-overview"
    >
      <v-alert
        v-if="overview && keyBanner"
        :type="keyBanner.status === 'ok' ? 'success' : keyBanner.status === 'warn' ? 'warning' : 'error'"
        variant="tonal"
        class="conflict"
        data-testid="backup-key-banner"
      >
        {{ t(keyBanner.label) }}
        <template #append>
          <v-btn
            variant="text"
            @click="setTab('key')"
          >
            {{ t('backup.tabs.key') }}
          </v-btn>
        </template>
      </v-alert>
      <div class="form-actions">
        <v-btn
          color="primary"
          :disabled="pending || !overview?.key.active"
          data-testid="backup-run-now"
          @click="onRun"
        >
          {{ t('backup.run.now') }}
        </v-btn>
        <v-btn
          variant="tonal"
          :disabled="pending"
          data-testid="backup-plan-restore"
          @click="openPlan"
        >
          {{ t('backup.restore.planAction') }}
        </v-btn>
      </div>
      <h2 class="pd-type-section">
        {{ t('backup.overview.grid') }}
      </h2>
      <p
        v-if="overview && overview.targets.length === 0"
        class="pd-muted"
        data-testid="backup-no-targets"
      >
        {{ t('backup.overview.noTargets') }}
      </p>
      <v-table
        v-else-if="overview"
        data-testid="backup-grid"
      >
        <thead>
          <tr>
            <th scope="col">
              {{ t('common.name') }}
            </th>
            <th
              v-for="kind in backupKinds"
              :key="kind"
              scope="col"
            >
              {{ t('backup.kinds.' + kind) }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="target in overview.targets"
            :key="target.id"
          >
            <th scope="row">
              {{ target.name }}
            </th>
            <td
              v-for="kind in backupKinds"
              :key="kind"
            >
              <StatusChip
                :status="kindStatus(target, kind).status"
                :label="t(kindStatus(target, kind).label)"
              />
              <TimeCell
                v-if="target.status.find((s) => s.kind === kind)?.last_success_at"
                :iso="target.status.find((s) => s.kind === kind)!.last_success_at!"
                mode="relative"
              />
            </td>
          </tr>
        </tbody>
      </v-table>
      <template v-if="overview">
        <h2 class="pd-type-section">
          {{ t('backup.overview.repo') }}
        </h2>
        <p data-testid="backup-repo">
          {{ overview.repo.bytes_used === null
            ? t('backup.overview.repoUnknown')
            : t('backup.overview.repoUsage', { used: sizeText(overview.repo.bytes_used), free: sizeText(overview.repo.bytes_free) }) }}
        </p>
        <h2 class="pd-type-section">
          {{ t('backup.overview.lastRuns') }}
        </h2>
        <ul data-testid="backup-last-runs">
          <li
            v-for="r in overview.last_runs"
            :key="r.id"
          >
            {{ t('backup.kinds.' + r.kind) }}:
            {{ r.outcome ? t('backup.outcomes.' + r.outcome) : t('backup.states.' + r.state) }}
            <TimeCell
              v-if="r.finished_at ?? r.started_at"
              :iso="(r.finished_at ?? r.started_at)!"
              mode="relative"
            />
          </li>
        </ul>
      </template>
    </div>

    <div
      v-else-if="tab === 'targets'"
      role="tabpanel"
      data-testid="backup-panel-targets"
    >
      <div class="form-actions">
        <v-btn
          color="primary"
          data-testid="create-backup-target"
          @click="openCreate"
        >
          {{ t('backup.targets.create') }}
        </v-btn>
      </div>
      <DataList
        ref="targetList"
        :columns="targetColumns"
        :fetch="fetchTargets"
        :filters="targetFilters"
        searchable
        default-sort="name"
        item-value="id"
        empty-icon="hard-drive"
        empty-title="backup.targets.empty.title"
        empty-description="backup.targets.empty.description"
        tabindex="-1"
        data-testid="backup-target-list"
      >
        <template #empty-action>
          <v-btn
            color="primary"
            @click="openCreate"
          >
            {{ t('backup.targets.create') }}
          </v-btn>
        </template>
        <template #[`item.type`]="{ item }: { item: BackupTarget }">
          {{ t('backup.targets.types.' + item.type) }}
        </template>
        <template #[`item.enabled`]="{ item }: { item: BackupTarget }">
          {{ t(item.enabled ? 'backup.on' : 'backup.off') }}
        </template>
        <template #[`item.host_state`]="{ item }: { item: BackupTarget }">
          <StatusChip
            :status="hostStateStatus(item.host_state).status"
            :label="t(hostStateStatus(item.host_state).label)"
            :data-testid="'backup-host-state-' + item.name"
          />
        </template>
        <template #[`item.test`]="{ item }: { item: BackupTarget }">
          <StatusChip
            :status="testStatus(item).status"
            :label="t(testStatus(item).label)"
            :data-testid="'backup-test-state-' + item.name"
          />
          <span
            v-if="item.last_test_ok === false && item.last_test_error"
            class="mono pd-muted"
          > {{ item.last_test_error }}</span>
        </template>
        <template #[`item.actions`]="{ item }: { item: BackupTarget }">
          <div class="form-actions">
            <v-btn
              :aria-label="t('backup.targets.testLabel', { name: item.name })"
              size="small"
              variant="tonal"
              :disabled="pending"
              @click="onTest(item, $event)"
            >
              {{ t('backup.targets.test') }}
            </v-btn>
            <v-btn
              :aria-label="t(item.enabled ? 'backup.targets.disableLabel' : 'backup.targets.enableLabel', { name: item.name })"
              size="small"
              variant="tonal"
              :disabled="pending"
              @click="onToggle(item, $event)"
            >
              {{ t(item.enabled ? 'backup.targets.disable' : 'backup.targets.enable') }}
            </v-btn>
            <v-btn
              :aria-label="t('backup.targets.editLabel', { name: item.name })"
              size="small"
              variant="tonal"
              @click="openEdit(item, $event)"
            >
              {{ t('common.edit') }}
            </v-btn>
            <v-btn
              :aria-label="t('backup.targets.deleteLabel', { name: item.name })"
              color="error"
              size="small"
              :disabled="pending"
              @click="onDelete(item, $event)"
            >
              {{ t('common.delete') }}
            </v-btn>
          </div>
        </template>
      </DataList>
    </div>

    <div
      v-else-if="tab === 'key'"
      role="tabpanel"
      data-testid="backup-panel-key"
    >
      <template v-if="overview">
        <v-alert
          v-if="overview.key.pending"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="backup-key-pending"
        >
          {{ t('backup.key.pendingText', { fingerprint: overview.key.pending.fingerprint }) }}
          <template #append>
            <v-btn
              variant="text"
              data-testid="backup-key-open-confirm"
              @click="openKeyConfirm"
            >
              {{ t('backup.key.confirmNow') }}
            </v-btn>
          </template>
        </v-alert>
        <section
          v-if="overview.key.active"
          aria-labelledby="backup-key-active"
        >
          <h2
            id="backup-key-active"
            class="pd-type-section"
          >
            {{ t('backup.key.active') }}
          </h2>
          <p
            class="mono"
            data-testid="backup-key-fingerprint"
          >
            {{ overview.key.active.fingerprint }}
          </p>
          <p class="pd-muted">
            {{ t('backup.key.activeSince', { by: overview.key.active.confirmed_by ?? '' }) }}
            <TimeCell
              v-if="overview.key.active.confirmed_at"
              :iso="overview.key.active.confirmed_at"
            />
          </p>
        </section>
        <p
          v-else-if="!overview.key.pending"
          data-testid="backup-key-none"
        >
          {{ t('backup.key.stateNone') }}
        </p>
        <div class="form-actions">
          <v-btn
            color="primary"
            :disabled="pending || overview.key.pending !== null"
            data-testid="backup-key-start"
            @click="openKeyStart"
          >
            {{ t(overview.key.active ? 'backup.key.rotate' : 'backup.key.create') }}
          </v-btn>
        </div>
        <h2 class="pd-type-section">
          {{ t('backup.key.retired') }}
        </h2>
        <DataList
          ref="retiredList"
          :columns="retiredColumns"
          :fetch="fetchRetired"
          default-sort="-retired_at"
          item-value="key_id"
          query-prefix="retired"
          empty-icon="key"
          empty-title="backup.key.noRetired"
          data-testid="backup-retired-list"
        >
          <template #[`item.created_at`]="{ item }: { item: BackupKey }">
            <TimeCell :iso="item.created_at" />
          </template>
          <template #[`item.retired_at`]="{ item }: { item: BackupKey }">
            <TimeCell
              v-if="item.retired_at"
              :iso="item.retired_at"
            />
          </template>
        </DataList>
      </template>
    </div>

    <div
      v-else-if="tab === 'schedule'"
      role="tabpanel"
      data-testid="backup-panel-schedule"
    >
      <form
        class="form"
        novalidate
        data-testid="backup-schedule-form"
        @submit.prevent="onSchedule"
      >
        <v-text-field
          v-for="field in scheduleFields()"
          :id="'backup-schedule-' + field"
          :key="field"
          v-model.number="schedule[field]"
          :label="t('backup.schedule.fields.' + field)"
          :hint="t('backup.schedule.range', { min: scheduleRanges[field][0], max: scheduleRanges[field][1] })"
          persistent-hint
          type="number"
          :error-messages="invalidSchedule.includes(field) ? [t('backup.schedule.invalid', { min: scheduleRanges[field][0], max: scheduleRanges[field][1] })] : []"
        />
        <div class="form-actions">
          <v-btn
            type="submit"
            color="primary"
            :loading="pending"
            :disabled="pending"
            data-testid="backup-schedule-save"
          >
            {{ t('common.save') }}
          </v-btn>
        </div>
      </form>
    </div>

    <div
      v-else-if="tab === 'restore'"
      role="tabpanel"
      data-testid="backup-panel-restore"
    >
      <div class="form-actions">
        <v-btn
          color="primary"
          data-testid="backup-plan-restore-tab"
          @click="openPlan"
        >
          {{ t('backup.restore.planAction') }}
        </v-btn>
      </div>
      <DataList
        ref="planList"
        :columns="planColumns"
        :fetch="fetchPlans"
        :filters="planFilters"
        searchable
        default-sort="-created_at"
        item-value="id"
        empty-icon="hard-drive"
        empty-title="backup.restore.empty.title"
        empty-description="backup.restore.empty.description"
        tabindex="-1"
        data-testid="backup-plan-list"
      >
        <template #[`item.created_at`]="{ item }: { item: BackupRestorePlan }">
          <TimeCell :iso="item.created_at" />
        </template>
        <template #[`item.kind`]="{ item }: { item: BackupRestorePlan }">
          {{ t('backup.restore.kinds.' + item.kind) }}
        </template>
        <template #[`item.state`]="{ item }: { item: BackupRestorePlan }">
          <StatusChip
            :status="planStateStatus(item.state).status"
            :label="t(planStateStatus(item.state).label)"
          />
          <span
            v-if="item.outcome_detail"
            class="mono pd-muted"
          > {{ item.outcome_detail }}</span>
        </template>
        <template #[`item.source`]="{ item }: { item: BackupRestorePlan }">
          {{ planSource(item) }}
        </template>
        <template #[`item.at`]="{ item }: { item: BackupRestorePlan }">
          <TimeCell
            v-if="item.at"
            :iso="item.at"
          />
          <span
            v-else
            class="pd-muted"
          >{{ t('backup.restore.newest') }}</span>
        </template>
        <template #[`item.components`]="{ item }: { item: BackupRestorePlan }">
          {{ item.components.map((c) => t('backup.restore.componentNames.' + c)).join(', ') }}
        </template>
        <template #[`item.actions`]="{ item }: { item: BackupRestorePlan }">
          <div
            v-if="item.state === 'approved'"
            class="form-actions"
          >
            <v-btn
              :aria-label="t('backup.restore.showLabel', { time: formatDateTime(item.created_at, locale) })"
              size="small"
              variant="tonal"
              @click="showPlan(item, $event)"
            >
              {{ t('backup.restore.showCommand') }}
            </v-btn>
            <v-btn
              :aria-label="t('backup.restore.cancelLabel', { time: formatDateTime(item.created_at, locale) })"
              color="error"
              size="small"
              :disabled="pending"
              :data-testid="'backup-plan-cancel-' + item.id"
              @click="onCancelPlan(item, $event)"
            >
              {{ t('backup.restore.cancelAction') }}
            </v-btn>
          </div>
          <v-btn
            v-else-if="item.state === 'running'"
            :aria-label="t('backup.restore.abandonLabel', { time: formatDateTime(item.created_at, locale) })"
            color="error"
            size="small"
            :disabled="pending"
            :data-testid="'backup-plan-abandon-' + item.id"
            @click="onAbandonPlan(item, $event)"
          >
            {{ t('backup.restore.abandonAction') }}
          </v-btn>
        </template>
      </DataList>
    </div>

    <div
      v-else
      role="tabpanel"
      data-testid="backup-panel-history"
    >
      <DataList
        ref="runList"
        :columns="runColumns"
        :fetch="fetchRuns"
        :filters="runFilters"
        default-sort="-started_at"
        item-value="id"
        empty-icon="hard-drive"
        empty-title="backup.runs.empty.title"
        empty-description="backup.runs.empty.description"
        tabindex="-1"
        data-testid="backup-run-list"
      >
        <template #[`item.started_at`]="{ item }: { item: BackupRun }">
          <TimeCell
            v-if="item.started_at"
            :iso="item.started_at"
          />
          <span
            v-else
            class="pd-muted"
          >{{ t('backup.states.requested') }}</span>
        </template>
        <template #[`item.kind`]="{ item }: { item: BackupRun }">
          {{ t('backup.kinds.' + item.kind) }}
        </template>
        <template #[`item.outcome`]="{ item }: { item: BackupRun }">
          <StatusChip
            v-if="item.outcome"
            :status="item.outcome === 'succeeded' ? 'ok' : 'critical'"
            :label="t('backup.outcomes.' + item.outcome)"
          />
          <StatusChip
            v-else
            status="info"
            :label="t('backup.states.' + item.state)"
          />
          <span
            v-if="item.error_class"
            class="mono pd-muted"
          > {{ item.error_class }}</span>
        </template>
        <template #[`item.bytes`]="{ item }: { item: BackupRun }">
          {{ sizeText(item.bytes) }}
        </template>
        <template #[`item.targets`]="{ item }: { item: BackupRun }">
          {{ t('backup.runs.targetsOk', { ok: item.targets.filter((x) => x.ok).length, total: item.targets.length }) }}
          <span
            v-if="item.targets.some((x) => x.error_class === 'continues')"
            class="pd-muted"
            data-testid="backup-run-continues"
          > {{ t('backup.runs.continues') }}</span>
        </template>
      </DataList>
    </div>

    <v-dialog
      :model-value="targetDialog !== null"
      max-width="44rem"
      :aria-label="dialogTitle"
      persistent
      @update:model-value="(v: boolean) => !v && closeTargetDialog()"
      @keydown.esc.stop="closeTargetDialog"
    >
      <v-card :title="dialogTitle">
        <v-card-text>
          <v-alert
            v-if="reenterCredentials"
            type="info"
            variant="tonal"
            class="conflict"
            data-testid="backup-reenter-credentials"
          >
            {{ t('backup.targets.reenter') }}
          </v-alert>
          <BackupTargetForm
            v-if="targetDialog"
            :key="targetKey"
            :initial="targetDialog.editing"
            :restored="targetDialog.restored"
            :problem="targetProblem"
            :pending="pending"
            @submit="(input: TargetInput) => run(() => submitTarget(input))"
            @cancel="closeTargetDialog"
          />
        </v-card-text>
      </v-card>
    </v-dialog>

    <BackupRestorePlanDialog
      v-if="planDialog"
      :overview="overview"
      :plan="planDialog.plan"
      :problem="planProblem"
      :pending="pending"
      @submit="(input: PlanInput) => run(() => execute({ op: 'plan', input }, true))"
      @close="closePlanDialog"
    />

    <BackupKeyDialog
      v-if="keyDialog"
      :step="keyDialog.step"
      :key-info="keyInfo"
      :attempts-left="keyAttempts"
      :problem="keyProblem"
      :pending="pending"
      @generate="onGenerate"
      @next="keyDialog = { step: 3 }"
      @confirm="onKeyConfirm"
      @discard="onKeyDiscard"
      @cancel="cancelKeyStart"
    />
  </section>
</template>
