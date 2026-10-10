<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import DataList from '../components/DataList.vue'
import IpAllowlistEntryForm from '../components/IpAllowlistEntryForm.vue'
import IpAllowlistStatus from '../components/IpAllowlistStatus.vue'
import type { IpAllowlistConfirm, IpAllowlistEntry } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { formatDateTime } from '../lib/format'
import {
  confirmationOf, createIpAllowlistEntry, deleteIpAllowlistEntry, listIpAllowlist, loadIpAllowlistStatus,
  updateIpAllowlistEntry, type IpAllowlistInput, type IpAllowlistStatus as Status,
} from '../lib/ipAllowlist'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/** One write of the page; it is kept across a step-up and repeated once (plan M7a decision 25). */
type Operation =
  | { op: 'create'; input: IpAllowlistInput; confirm?: IpAllowlistConfirm }
  | { op: 'update'; id: string; cidr: string; input: IpAllowlistInput; confirm?: IpAllowlistConfirm }
  | { op: 'delete'; id: string; cidr: string; confirm?: IpAllowlistConfirm }

const stepUpAction = 'ip-allowlist'

const { t, locale } = useI18n()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)

const clientIp = computed(() => session.me?.client_ip ?? '')
const status = ref<Status | null>(null)
const statusProblem = ref('')
const pageProblem = ref('')
const saved = ref('')

/** The open dialog: a new entry or the entry being edited. */
const dialog = ref<{ editing: IpAllowlistEntry | null } | null>(null)
const problem = ref('')
const formKey = ref(0)

const columns: ListColumn[] = [
  { key: 'cidr', title: 'ipAllowlist.cidr', sortable: true },
  { key: 'label', title: 'ipAllowlist.label', sortable: true },
  { key: 'created_by', title: 'ipAllowlist.createdBy' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  { key: 'actions', title: 'common.actions' },
]

async function loadStatus(): Promise<void> {
  const res = await loadIpAllowlistStatus()
  if (typeof res === 'string') {
    statusProblem.value = res
    return
  }
  statusProblem.value = ''
  status.value = res
}

onMounted(async () => {
  await loadStatus()
  const resumed = resumeStepUp<Operation>(stepUpAction, stepUpAction)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    pageProblem.value = 'step_up_failed'
    return
  }
  if (resumed.payload.op !== 'delete') {
    dialog.value = { editing: null }
  }
  await run(resumed.payload, false)
})

function openCreate(): void {
  problem.value = ''
  formKey.value++
  dialog.value = { editing: null }
}

function openEdit(entry: IpAllowlistEntry): void {
  problem.value = ''
  formKey.value++
  dialog.value = { editing: entry }
}

function closeDialog(): void {
  dialog.value = null
}

async function refresh(): Promise<void> {
  await Promise.all([loadStatus(), list.value?.reload()])
}

/** Sends the operation once; a step-up is started on step_up_required, a 409 asks for the typed confirmation. */
async function run(operation: Operation, stepUp: boolean): Promise<void> {
  saved.value = ''
  const code = await perform(operation)
  if (code === null) {
    dialog.value = null
    saved.value = t('ipAllowlist.saved')
    await refresh()
    return
  }
  if (code === stepUpRequired && stepUp) {
    startStepUp(stepUpAction, stepUpAction, operation)
    return
  }
  const needed = confirmationOf(code)
  if (needed) {
    const cidr = operation.op === 'create' ? operation.input.cidr : operation.cidr
    const confirmed = await confirm({
      title: t(needed === 'lockout' ? 'ipAllowlist.confirmLockoutTitle' : 'ipAllowlist.confirmDisableTitle'),
      message: t(needed === 'lockout' ? 'ipAllowlist.confirmLockout' : 'ipAllowlist.confirmDisable', { ip: clientIp.value }),
      confirmLabel: t('ipAllowlist.confirmChange'),
      destructive: true,
      requireTypedText: cidr,
    })
    if (!confirmed) return
    await run({ ...operation, confirm: needed }, stepUp)
    return
  }
  if (operation.op === 'delete') pageProblem.value = code
  else problem.value = code
}

async function perform(operation: Operation): Promise<string | null> {
  switch (operation.op) {
    case 'create': {
      const res = await createIpAllowlistEntry(operation.input, operation.confirm)
      return typeof res === 'string' ? res : null
    }
    case 'update': {
      const res = await updateIpAllowlistEntry(operation.id, operation.input, operation.confirm)
      return typeof res === 'string' ? res : null
    }
    case 'delete':
      return deleteIpAllowlistEntry(operation.id, operation.confirm)
  }
}

function submit(input: IpAllowlistInput): void {
  problem.value = ''
  const editing = dialog.value?.editing
  void run(editing ? { op: 'update', id: editing.id, cidr: editing.cidr, input } : { op: 'create', input }, true)
}

async function onRemove(entry: IpAllowlistEntry): Promise<void> {
  pageProblem.value = ''
  const confirmed = await confirm({
    title: t('ipAllowlist.removeTitle'),
    message: t('ipAllowlist.removeConfirm', { cidr: entry.cidr, label: entry.label }),
    confirmLabel: t('ipAllowlist.remove'),
    destructive: true,
  })
  if (!confirmed) return
  await run({ op: 'delete', id: entry.id, cidr: entry.cidr }, true)
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('ipAllowlist.title') }}</h1>
      <v-btn
        color="primary"
        data-testid="create-ip-allowlist-entry"
        @click="openCreate"
      >
        {{ t('ipAllowlist.add') }}
      </v-btn>
    </div>
    <p class="summary">
      {{ t('ipAllowlist.summary') }}
    </p>
    <IpAllowlistStatus
      v-if="status"
      :client-ip="clientIp"
      :entries="status.entries"
      :covering="status.covering"
    />
    <p
      v-if="statusProblem"
      class="form-error"
      role="alert"
    >
      {{ problemText(statusProblem) }}
    </p>
    <p
      v-if="pageProblem"
      class="form-error"
      role="alert"
    >
      {{ problemText(pageProblem) }}
    </p>
    <p
      v-if="saved"
      role="status"
      data-testid="ip-allowlist-saved"
    >
      {{ saved }}
    </p>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listIpAllowlist"
      searchable
      default-sort="cidr"
      item-value="id"
      data-testid="ip-allowlist-list"
    >
      <template #[`item.cidr`]="{ item }: { item: IpAllowlistEntry }">
        <code>{{ item.cidr }}</code>
        <v-chip
          v-if="item.covers_caller"
          size="x-small"
          color="success"
          variant="tonal"
          class="ml-2"
          data-testid="covers-caller"
        >
          {{ t('ipAllowlist.coversYou') }}
        </v-chip>
      </template>
      <template #[`item.created_at`]="{ item }: { item: IpAllowlistEntry }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
      <template #[`item.actions`]="{ item }: { item: IpAllowlistEntry }">
        <v-btn
          :aria-label="t('ipAllowlist.editLabel', { cidr: item.cidr })"
          size="small"
          variant="tonal"
          class="mr-2"
          @click="openEdit(item)"
        >
          {{ t('common.edit') }}
        </v-btn>
        <v-btn
          :aria-label="t('ipAllowlist.removeLabel', { cidr: item.cidr })"
          color="error"
          size="small"
          @click="onRemove(item)"
        >
          {{ t('ipAllowlist.remove') }}
        </v-btn>
      </template>
    </DataList>

    <v-dialog
      :model-value="dialog !== null"
      max-width="40rem"
      :aria-label="dialog?.editing ? t('ipAllowlist.editTitle') : t('ipAllowlist.addTitle')"
      persistent
      @update:model-value="(v: boolean) => !v && closeDialog()"
    >
      <v-card :title="dialog?.editing ? t('ipAllowlist.editTitle') : t('ipAllowlist.addTitle')">
        <v-card-text>
          <IpAllowlistEntryForm
            :key="formKey"
            :client-ip="clientIp"
            :initial="dialog?.editing ? { cidr: dialog.editing.cidr, label: dialog.editing.label } : null"
            :problem="problem"
            @submit="submit"
            @cancel="closeDialog"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
