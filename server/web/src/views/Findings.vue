<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Finding } from '../api/client'
import DataList from '../components/DataList.vue'
import FindingAssignDialog from '../components/FindingAssignDialog.vue'
import FindingCloseDialog from '../components/FindingCloseDialog.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import { useConfirm } from '../composables/useConfirm'
import { useFocusReturn } from '../composables/useFocusReturn'
import { usePending } from '../composables/usePending'
import {
  acknowledgeFinding, assignFinding, closeFinding, findingTitle, findingFilters, listFindings, maxFindingReason, reopenFinding,
  type CloseInput, type FindingResult,
} from '../lib/findings'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { findingStatus } from '../lib/status'
import { useSessionStore } from '../stores/session'

/**
 * Findings (plan M9 decision 35): tamper events and attention conditions with their status. Administrators and
 * operators acknowledge, assign, close and reopen; every step is a modal and an audit event, auditors only read.
 */
const { t, te } = useI18n()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const { pending, run } = usePending()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const pageProblem = ref('')
const done = ref('')
const assigning = ref<Finding | null>(null)
const closing = ref<Finding | null>(null)
const dialogProblem = ref('')
const focusReturn = useFocusReturn()

const doneAlert = ref<{ $el: HTMLElement } | null>(null)

function closeDialogs(): void {
  assigning.value = null
  closing.value = null
  // A closed finding leaves the default list, so the result message is where focus continues.
  focusReturn.restore(() => doneAlert.value?.$el ?? document.querySelector<HTMLElement>('[data-testid="finding-list"]'))
}

const columns = computed<ListColumn[]>(() => [
  { key: 'code', title: 'findings.code', sortable: true, role: 'primary' },
  { key: 'status', title: 'findings.statusColumn', sortable: true, role: 'status' },
  { key: 'hostname', title: 'findings.device', sortable: true, role: 'meta' },
  { key: 'occurrences', title: 'findings.occurrences', role: 'meta', hideBelow: 'md', align: 'end' },
  { key: 'assignee', title: 'findings.assignee', role: 'meta', hideBelow: 'sm' },
  { key: 'last_seen_at', title: 'findings.lastSeen', sortable: true, role: 'meta', hideBelow: 'sm' },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions', role: 'actions' as const }] : []),
])

const closed = (f: Finding) => f.closed_at !== null
const canAcknowledge = (f: Finding) => f.status === 'open'
const canAssign = (f: Finding) => !closed(f) && f.cleared_at === null
const canClose = (f: Finding) => !closed(f)

const title = (f: Finding) => findingTitle(f, t, te)

/** Shows the outcome inline: the new status of the finding or the problem; the list reloads on success. */
async function settle(result: FindingResult, f: Finding): Promise<boolean> {
  if (typeof result === 'string') {
    pageProblem.value = result
    done.value = ''
    return false
  }
  pageProblem.value = ''
  done.value = t('findings.done', { finding: title(f), status: t('findings.status.' + result.status) })
  await list.value?.reload()
  return true
}

async function acknowledge(f: Finding): Promise<void> {
  const ok = await confirm({
    title: t('findings.acknowledge.title'),
    message: t('findings.acknowledge.message', { finding: title(f) }),
    confirmLabel: t('findings.acknowledge.confirm'),
  })
  if (ok) void settle(await acknowledgeFinding(f.id), f)
}

async function reopen(f: Finding): Promise<void> {
  const answer = await confirm({
    title: t('findings.reopen.title'),
    message: t('findings.reopen.message', { finding: title(f) }),
    confirmLabel: t('findings.reopen.confirm'),
    reason: { label: t('findings.reopen.reason'), hint: t('findings.close.reasonHint'), required: true, maxLength: maxFindingReason },
  })
  if (answer) void settle(await reopenFinding(f.id, answer.reason), f)
}

function openAssign(f: Finding, event: Event): void {
  focusReturn.remember(event)
  dialogProblem.value = ''
  assigning.value = f
}

function openClose(f: Finding, event: Event): void {
  focusReturn.remember(event)
  dialogProblem.value = ''
  closing.value = f
}

async function submitAssign(assigneeID: string | null): Promise<void> {
  const f = assigning.value
  if (!f) return
  const result = await assignFinding(f.id, assigneeID)
  if (typeof result === 'string') dialogProblem.value = result
  else if (await settle(result, f)) closeDialogs()
}

async function submitClose(input: CloseInput): Promise<void> {
  const f = closing.value
  if (!f) return
  const result = await closeFinding(f.id, input)
  if (typeof result === 'string') dialogProblem.value = result
  else if (await settle(result, f)) closeDialogs()
}
</script>

<template>
  <section class="page">
    <h1>{{ t('findings.title') }}</h1>
    <p class="summary">
      {{ t('findings.summary') }}
    </p>
    <v-alert
      v-if="done"
      ref="doneAlert"
      tabindex="-1"
      type="success"
      variant="tonal"
      closable
      class="conflict"
      role="status"
      data-testid="finding-done"
      @click:close="done = ''"
    >
      {{ done }}
    </v-alert>
    <v-alert
      v-if="pageProblem"
      type="error"
      variant="tonal"
      closable
      class="conflict"
      role="alert"
      data-testid="finding-problem"
      @click:close="pageProblem = ''"
    >
      {{ problemText(pageProblem) }}
    </v-alert>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listFindings"
      :filters="findingFilters"
      searchable
      default-sort="-last_seen_at"
      item-value="id"
      empty-icon="circle-check"
      empty-title="findings.empty.title"
      empty-description="findings.empty.description"
      data-testid="finding-list"
    >
      <template #[`item.code`]="{ item }: { item: Finding }">
        <span
          class="pd-truncate"
          :title="title(item)"
        >{{ item.kind === 'attention' ? t('attention.kinds.' + item.code) : title(item) }}</span>
        <span class="pd-type-caption pd-muted pd-block">
          {{ t('findings.kinds.' + item.kind) }} · <span class="mono">{{ item.code }}</span><template v-if="item.subject"> · <span class="mono">{{ item.subject }}</span></template>
        </span>
      </template>
      <template #[`item.status`]="{ item }: { item: Finding }">
        <StatusChip
          :status="findingStatus(item.status).status"
          :label="t(findingStatus(item.status).label)"
          :data-testid="'finding-status-' + item.status"
        />
        <StatusChip
          v-if="item.cleared_at"
          status="neutral"
          :label="t('findings.cleared')"
          :title="t('findings.clearedHint')"
        />
      </template>
      <template #[`item.hostname`]="{ item }: { item: Finding }">
        <RouterLink
          :to="{ name: 'device', params: { id: item.device_id } }"
          class="mono pd-truncate"
          :title="item.hostname"
        >
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.assignee`]="{ item }: { item: Finding }">
        <span v-if="item.assignee">{{ item.assignee.display_name || item.assignee.username }}</span>
        <span
          v-else
          class="pd-muted"
        >–</span>
      </template>
      <template #[`item.last_seen_at`]="{ item }: { item: Finding }">
        <TimeCell
          :iso="item.last_seen_at"
          mode="relative"
        />
      </template>
      <template #[`item.actions`]="{ item }: { item: Finding }">
        <div class="row-actions pd-finding-actions">
          <v-btn
            v-if="canAcknowledge(item)"
            size="small"
            variant="tonal"
            :disabled="pending"
            :aria-label="t('findings.acknowledge.label', { finding: title(item) })"
            @click="run(() => acknowledge(item))"
          >
            {{ t('findings.acknowledge.action') }}
          </v-btn>
          <v-btn
            v-if="canAssign(item)"
            size="small"
            variant="tonal"
            :aria-label="t('findings.assign.label', { finding: title(item) })"
            @click="openAssign(item, $event)"
          >
            {{ t('findings.assign.action') }}
          </v-btn>
          <v-btn
            v-if="canClose(item)"
            size="small"
            variant="tonal"
            :aria-label="t('findings.close.label', { finding: title(item) })"
            @click="openClose(item, $event)"
          >
            {{ t('findings.close.action') }}
          </v-btn>
          <v-btn
            v-if="closed(item)"
            size="small"
            variant="tonal"
            :disabled="pending"
            :aria-label="t('findings.reopen.label', { finding: title(item) })"
            @click="run(() => reopen(item))"
          >
            {{ t('findings.reopen.action') }}
          </v-btn>
        </div>
      </template>
    </DataList>

    <FindingAssignDialog
      v-if="assigning"
      :key="assigning.id"
      :model-value="true"
      :finding="assigning"
      :problem="dialogProblem"
      :pending="pending"
      @submit="run(() => submitAssign($event))"
      @cancel="closeDialogs"
    />
    <FindingCloseDialog
      v-if="closing"
      :key="closing.id"
      :model-value="true"
      :finding="closing"
      :admin="session.canDelete"
      :problem="dialogProblem"
      :pending="pending"
      @submit="run(() => submitClose($event))"
      @cancel="closeDialogs"
    />
  </section>
</template>

<style scoped>
/* Three actions plus the other columns overflow a 1280 px page, so the actions wrap onto a second line instead of
   clipping the column. */
.pd-finding-actions {
  flex-wrap: wrap;
  gap: var(--pd-space-1);
}
</style>
