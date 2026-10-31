<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import DataList from './DataList.vue'
import NotificationCursorDialog from './NotificationCursorDialog.vue'
import NotificationDestinationForm from './NotificationDestinationForm.vue'
import NotificationPseudonymDialog from './NotificationPseudonymDialog.vue'
import StatusChip from './StatusChip.vue'
import TimeCell from './TimeCell.vue'
import { useConfirm } from '../composables/useConfirm'
import { useFocusReturn } from '../composables/useFocusReturn'
import { usePending } from '../composables/usePending'
import type { ListColumn } from '../lib/listQuery'
import {
  backlogOf, createDestination, deleteDestination, destinationLister, getDestination, isProblem, lagParts,
  loadEmailCapability, loadLatestSeq, notificationFilters, pollUntil, pseudonymStepUpAction, requestTest, rotateSecret, stateStatus,
  updateDestination, type NotificationDestination, type NotificationInput, type NotificationProblem, type NotificationScope,
} from '../lib/notifications'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam, type Resumed } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The notification destinations of the organization or the platform (plan M9 decision 36, ADR 0031): a list with the
 * delivery state, a form dialog, the signing secret shown once, and delete, rotate and test behind a confirmation.
 * Every change needs a step-up; the refused action is repeated once when the browser comes back. A webhook URL is
 * a secret and never waits in the browser's storage, so a step-up that interrupts a typed URL asks for it again.
 */
const props = defineProps<{ scope: NotificationScope }>()

type Operation =
  | { op: 'create'; input: NotificationInput; hadUrl: boolean }
  | { op: 'update'; id: string; input: NotificationInput; hadUrl: boolean; cursor?: 'continue' | 'skip' }
  | { op: 'delete'; id: string; name: string }
  | { op: 'rotate'; id: string; name: string }
  | { op: 'test'; id: string; name: string }

const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const session = useSessionStore()
const focusReturn = useFocusReturn()
const list = ref<{ reload: () => Promise<void> } | null>(null)

const stepUpAction = 'notification-destination'
const canWrite = computed(() => (props.scope === 'platform' ? session.isPlatform : session.canDelete))
const fetchList = destinationLister(props.scope)

const emailAvailable = ref(false)
const dialog = ref<{ editing: NotificationDestination | null; restored: NotificationInput | null } | null>(null)
const formKey = ref(0)
const formProblem = ref<NotificationProblem | null>(null)
const pageProblem = ref('')
const saved = ref('')
const reenterUrl = ref(false)
/** The secret of a created destination or a rotation: shown once and dropped when the dialog closes. */
const secret = ref<{ name: string; value: string } | null>(null)
const copied = ref(false)
const cursorAsk = ref<{ destination: NotificationDestination; input: NotificationInput; backlog: number | null } | null>(null)
const pseudonymOpen = ref(false)
const pseudonymResumed = ref<Resumed<{ id: string; pseudonym: string }> | null>(null)
const testing = ref<{ name: string; phase: 'waiting' | 'ok' | 'error' | 'timeout'; error: string } | null>(null)
let cancelled = false

const columns = computed<ListColumn[]>(() => [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'type', title: 'notifications.type', sortable: true },
  { key: 'filter_mode', title: 'notifications.filterMode' },
  { key: 'enabled', title: 'notifications.enabled' },
  { key: 'state', title: 'notifications.state', role: 'status' },
  { key: 'last_success_at', title: 'notifications.lastSuccess' },
  { key: 'lag', title: 'notifications.lag' },
  ...(canWrite.value ? [{ key: 'actions', title: 'common.actions' }] : []),
])

onMounted(async () => {
  emailAvailable.value = await loadEmailCapability()
  if (props.scope === 'organization') {
    const lookup = resumeStepUp<{ id: string; pseudonym: string }>(pseudonymStepUpAction, props.scope)
    if (lookup) {
      await router.replace(withoutStepUpParam())
      pseudonymResumed.value = lookup
      pseudonymOpen.value = true
      return
    }
  }
  const resumed = resumeStepUp<Operation>(stepUpAction, props.scope)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    pageProblem.value = 'step_up_failed'
    return
  }
  const operation = resumed.payload
  if ((operation.op === 'create' || operation.op === 'update') && operation.hadUrl) {
    reenterUrl.value = true
    formProblem.value = null
    let editing: NotificationDestination | null = null
    if (operation.op === 'update') {
      const current = await getDestination(props.scope, operation.id)
      if (!isProblem(current)) editing = current
    }
    formKey.value++
    dialog.value = { editing, restored: operation.input }
    return
  }
  await execute(operation, false)
})
onBeforeUnmount(() => { cancelled = true })

function openCreate(event?: Event): void {
  focusReturn.remember(event)
  formProblem.value = null
  reenterUrl.value = false
  formKey.value++
  dialog.value = { editing: null, restored: null }
}

function openEdit(d: NotificationDestination, event?: Event): void {
  focusReturn.remember(event)
  formProblem.value = null
  reenterUrl.value = false
  formKey.value++
  dialog.value = { editing: d, restored: null }
}

function closeDialog(): void {
  dialog.value = null
  focusReturn.restore(() => document.querySelector<HTMLElement>('[data-testid="notification-list"]'))
}

function closeSecret(): void {
  secret.value = null
  copied.value = false
  focusReturn.restore(() => document.querySelector<HTMLElement>('[data-testid="notification-list"]'))
  void list.value?.reload()
}

async function copy(): Promise<void> {
  if (!secret.value) return
  await navigator.clipboard.writeText(secret.value.value)
  copied.value = true
}

function stripUrl(input: NotificationInput): NotificationInput {
  return { ...input, url: '' }
}

/** Sends the operation; step_up_required starts the step-up once and the page repeats the operation on return. */
async function execute(operation: Operation, stepUp: boolean): Promise<void> {
  saved.value = ''
  pageProblem.value = ''
  const answer = await perform(operation)
  if (answer === null) return
  if (answer.code === stepUpRequired && stepUp) {
    const payload = operation.op === 'create' || operation.op === 'update'
      ? { ...operation, input: stripUrl(operation.input), hadUrl: operation.input.url.trim() !== '' }
      : operation
    startStepUp(stepUpAction, props.scope, payload)
    return
  }
  if (operation.op === 'create' || operation.op === 'update') formProblem.value = answer
  else if (operation.op === 'test' && answer.code === 'invalid_state') pageProblem.value = 'notification_test_pending'
  else pageProblem.value = answer.code
}

/** Performs one operation; null on success (the page state is updated), otherwise the problem. */
async function perform(operation: Operation): Promise<NotificationProblem | null> {
  switch (operation.op) {
    case 'create': {
      const res = await createDestination(props.scope, operation.input)
      if (isProblem(res)) return res
      dialog.value = null
      saved.value = t('notifications.saved')
      if (res.secret) secret.value = { name: res.destination.name, value: res.secret }
      else focusReturn.restore()
      await list.value?.reload()
      return null
    }
    case 'update': {
      const res = await updateDestination(props.scope, operation.id, operation.input, operation.cursor)
      if (isProblem(res)) return res
      dialog.value = null
      focusReturn.restore()
      saved.value = t('notifications.saved')
      await list.value?.reload()
      return null
    }
    case 'delete': {
      const res = await deleteDestination(props.scope, operation.id)
      if (res) return res
      saved.value = t('notifications.deleted', { name: operation.name })
      focusReturn.restore(() => document.querySelector<HTMLElement>('[data-testid="notification-list"]'))
      await list.value?.reload()
      return null
    }
    case 'rotate': {
      const res = await rotateSecret(props.scope, operation.id)
      if (isProblem(res)) return res
      secret.value = { name: operation.name, value: res }
      return null
    }
    case 'test':
      return startTest(operation)
  }
}

async function startTest(operation: { id: string; name: string }): Promise<NotificationProblem | null> {
  const before = await getDestination(props.scope, operation.id)
  const baseline = isProblem(before) ? null : (before.state.last_test?.at ?? null)
  const refused = await requestTest(props.scope, operation.id)
  if (refused) return refused
  testing.value = { name: operation.name, phase: 'waiting', error: '' }
  const outcome = await pollUntil(async () => {
    const d = await getDestination(props.scope, operation.id)
    if (isProblem(d)) return { ok: false, error: d.code }
    const test = d.state.last_test
    return test && test.at !== baseline ? { ok: test.ok, error: test.error ?? '' } : null
  }, () => cancelled)
  if (outcome === null) testing.value = { name: operation.name, phase: 'timeout', error: '' }
  else testing.value = { name: operation.name, phase: outcome.ok ? 'ok' : 'error', error: outcome.error }
  void list.value?.reload()
  return null
}

/** Saves the form; enabling a disabled destination first asks where delivery resumes. */
async function submit(input: NotificationInput): Promise<void> {
  formProblem.value = null
  const editing = dialog.value?.editing ?? null
  if (!editing) {
    await execute({ op: 'create', input, hadUrl: false }, true)
    return
  }
  if (input.enabled && !editing.enabled) {
    cursorAsk.value = { destination: editing, input, backlog: props.scope === 'organization' ? backlogOf(await loadLatestSeq(), editing) : null }
    return
  }
  await execute({ op: 'update', id: editing.id, input, hadUrl: false }, true)
}

async function onCursor(cursor: 'continue' | 'skip'): Promise<void> {
  const ask = cursorAsk.value
  cursorAsk.value = null
  if (!ask) return
  await run(() => execute({ op: 'update', id: ask.destination.id, input: ask.input, hadUrl: false, cursor }, true))
}

async function onDelete(d: NotificationDestination, event?: Event): Promise<void> {
  focusReturn.remember(event)
  const confirmed = await confirm({
    title: t('notifications.deleteTitle'),
    message: t('notifications.deleteConfirm', { name: d.name }),
    confirmLabel: t('common.delete'),
    destructive: true,
    requireTypedText: d.name,
  })
  if (!confirmed) return
  await run(() => execute({ op: 'delete', id: d.id, name: d.name }, true))
}

async function onRotate(d: NotificationDestination, event?: Event): Promise<void> {
  focusReturn.remember(event)
  const confirmed = await confirm({
    title: t('notifications.rotateTitle'),
    message: t('notifications.rotateConfirm', { name: d.name }),
    confirmLabel: t('notifications.rotate'),
    destructive: true,
  })
  if (!confirmed) return
  await run(() => execute({ op: 'rotate', id: d.id, name: d.name }, true))
}

async function onTest(d: NotificationDestination, event?: Event): Promise<void> {
  focusReturn.remember(event)
  const confirmed = await confirm({
    title: t('notifications.testTitle'),
    message: t('notifications.testConfirm', { name: d.name }),
    confirmLabel: t('notifications.test'),
  })
  if (!confirmed) return
  await run(() => execute({ op: 'test', id: d.id, name: d.name }, true))
}

function openPseudonym(event?: Event): void {
  focusReturn.remember(event)
  pseudonymOpen.value = true
}

function closePseudonym(): void {
  pseudonymOpen.value = false
  pseudonymResumed.value = null
  focusReturn.restore()
}

function lagText(seconds: number): string {
  const { unit, value } = lagParts(seconds)
  return t('notifications.lagValue.' + unit, { value })
}

const dialogTitle = computed(() => (dialog.value?.editing ? t('notifications.editTitle') : t('notifications.createTitle')))
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t(scope === 'platform' ? 'notifications.platformTitle' : 'notifications.title') }}</h1>
      <div class="form-actions">
        <v-btn
          v-if="scope === 'organization' && canWrite"
          variant="tonal"
          data-testid="resolve-pseudonym"
          @click="openPseudonym"
        >
          {{ t('notifications.pseudonym.open') }}
        </v-btn>
        <v-btn
          v-if="canWrite"
          color="primary"
          data-testid="create-notification"
          @click="openCreate"
        >
          {{ t('notifications.create') }}
        </v-btn>
      </div>
    </div>
    <p class="summary">
      {{ t(scope === 'platform' ? 'notifications.platformSummary' : 'notifications.summary') }}
    </p>
    <p
      v-if="pageProblem"
      class="form-error"
      role="alert"
      data-testid="notification-page-problem"
    >
      {{ problemText(pageProblem) }}
    </p>
    <p
      v-if="saved"
      role="status"
      data-testid="notification-saved"
    >
      {{ saved }}
    </p>
    <v-alert
      v-if="testing"
      :type="testing.phase === 'ok' ? 'success' : testing.phase === 'waiting' ? 'info' : 'warning'"
      variant="tonal"
      class="conflict"
      role="status"
      closable
      data-testid="notification-test-result"
      @click:close="testing = null"
    >
      <template v-if="testing.phase === 'waiting'">
        {{ t('notifications.testWaiting', { name: testing.name }) }}
      </template>
      <template v-else-if="testing.phase === 'ok'">
        {{ t('notifications.testOk', { name: testing.name }) }}
      </template>
      <template v-else-if="testing.phase === 'error'">
        {{ t('notifications.testError', { name: testing.name, error: testing.error || t('notifications.testUnknown') }) }}
      </template>
      <template v-else>
        {{ t('notifications.testTimeout', { name: testing.name }) }}
      </template>
    </v-alert>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="fetchList"
      :filters="notificationFilters"
      searchable
      default-sort="name"
      item-value="id"
      empty-icon="bell"
      empty-title="notifications.empty.title"
      empty-description="notifications.empty.description"
      tabindex="-1"
      data-testid="notification-list"
    >
      <template #empty-action>
        <v-btn
          v-if="canWrite"
          color="primary"
          @click="openCreate"
        >
          {{ t('notifications.create') }}
        </v-btn>
      </template>
      <template #[`item.type`]="{ item }: { item: NotificationDestination }">
        {{ t('notifications.types.' + item.type) }}
        <span
          v-if="item.url_display"
          class="mono pd-muted"
          data-testid="notification-url-display"
        >{{ item.url_display }}</span>
      </template>
      <template #[`item.filter_mode`]="{ item }: { item: NotificationDestination }">
        {{ t('notifications.modes.' + item.filter_mode) }}
        <span v-if="item.filter_mode === 'custom'">({{ item.codes.length }})</span>
      </template>
      <template #[`item.enabled`]="{ item }: { item: NotificationDestination }">
        {{ t(item.enabled ? 'notifications.on' : 'notifications.off') }}
      </template>
      <template #[`item.state`]="{ item }: { item: NotificationDestination }">
        <StatusChip
          :status="stateStatus(item).status"
          :label="t(stateStatus(item).label)"
          :data-testid="'notification-state-' + item.name"
        />
        <span
          v-if="item.enabled && item.state.last_error"
          class="mono pd-muted"
          data-testid="notification-last-error"
        > {{ item.state.last_error }}</span>
      </template>
      <template #[`item.last_success_at`]="{ item }: { item: NotificationDestination }">
        <TimeCell
          v-if="item.state.last_success_at"
          :iso="item.state.last_success_at"
          mode="relative"
        />
        <span
          v-else
          class="pd-muted"
        >{{ t('notifications.never') }}</span>
      </template>
      <template #[`item.lag`]="{ item }: { item: NotificationDestination }">
        {{ lagText(item.state.lag_seconds) }}
      </template>
      <template #[`item.actions`]="{ item }: { item: NotificationDestination }">
        <div class="form-actions">
          <v-btn
            :aria-label="t('notifications.editLabel', { name: item.name })"
            size="small"
            variant="tonal"
            @click="openEdit(item, $event)"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            :aria-label="t('notifications.testLabel', { name: item.name })"
            size="small"
            variant="tonal"
            :disabled="pending"
            @click="onTest(item, $event)"
          >
            {{ t('notifications.test') }}
          </v-btn>
          <v-btn
            v-if="item.type === 'webhook'"
            :aria-label="t('notifications.rotateLabel', { name: item.name })"
            size="small"
            variant="tonal"
            :disabled="pending"
            @click="onRotate(item, $event)"
          >
            {{ t('notifications.rotate') }}
          </v-btn>
          <v-btn
            :aria-label="t('notifications.deleteLabel', { name: item.name })"
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

    <v-dialog
      :model-value="dialog !== null"
      max-width="44rem"
      :aria-label="dialogTitle"
      persistent
      @update:model-value="(v: boolean) => !v && closeDialog()"
      @keydown.esc.stop="closeDialog"
    >
      <v-card :title="dialogTitle">
        <v-card-text>
          <v-alert
            v-if="reenterUrl"
            type="info"
            variant="tonal"
            class="conflict"
            data-testid="notification-reenter-url"
          >
            {{ t('notifications.reenterUrl') }}
          </v-alert>
          <NotificationDestinationForm
            v-if="dialog"
            :key="formKey"
            :scope="scope"
            :initial="dialog.editing"
            :restored="dialog.restored"
            :email-available="emailAvailable"
            :problem="formProblem"
            :pending="pending"
            @submit="(input: NotificationInput) => run(() => submit(input))"
            @cancel="closeDialog"
          />
        </v-card-text>
      </v-card>
    </v-dialog>

    <v-dialog
      :model-value="secret !== null"
      max-width="40rem"
      :aria-label="t('notifications.secretTitle')"
      persistent
      @keydown.esc.stop="closeSecret"
    >
      <v-card :title="t('notifications.secretTitle')">
        <v-card-text v-if="secret">
          <v-alert
            type="warning"
            variant="tonal"
          >
            {{ t('notifications.shownOnce', { name: secret.name }) }}
          </v-alert>
          <v-text-field
            :model-value="secret.value"
            :label="t('notifications.secret')"
            readonly
            class="config-text"
            data-testid="notification-secret"
          />
          <div class="form-actions">
            <span
              v-if="copied"
              role="status"
            >{{ t('tokens.copied') }}</span>
            <v-btn
              variant="tonal"
              data-testid="copy-notification-secret"
              @click="copy"
            >
              {{ t('tokens.copy') }}
            </v-btn>
            <v-btn
              color="primary"
              data-testid="close-notification-secret"
              @click="closeSecret"
            >
              {{ t('tokens.done') }}
            </v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>

    <NotificationCursorDialog
      :model-value="cursorAsk !== null"
      :name="cursorAsk?.destination.name ?? ''"
      :backlog="cursorAsk?.backlog ?? null"
      @choose="onCursor"
      @cancel="cursorAsk = null"
    />
    <NotificationPseudonymDialog
      v-if="pseudonymOpen"
      :resumed="pseudonymResumed"
      @close="closePseudonym"
    />
  </section>
</template>
