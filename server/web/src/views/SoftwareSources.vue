<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import DataList from '../components/DataList.vue'
import SoftwareSourceForm from '../components/SoftwareSourceForm.vue'
import TimeCell from '../components/TimeCell.vue'
import type { SoftwareSource, SoftwareSourceSummary } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import {
  deleteSoftwareSource, getSoftwareSource, groupFingerprint, listSoftwareSources, saveSoftwareSource, type SourceInput,
} from '../lib/software'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/** A save that waits for the step-up; the page repeats it once when the browser comes back (plan M13a decision 30). */
interface PendingSave { id: string | null; input: SourceInput; keyChanged: boolean }
interface PendingDelete { id: string }

const saveAction = 'software-source.save'
const deleteAction = 'software-source.delete'

const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const open = ref(false)
const target = ref<SoftwareSource | null>(null)
const draft = ref<SourceInput | null>(null)
const draftProblem = ref('')
const pageProblem = ref('')
const formKey = ref(0)

const columns: ListColumn[] = [
  { key: 'name', title: 'software.sources.name', sortable: true, role: 'primary' },
  { key: 'slug', title: 'software.sources.slug', role: 'meta' },
  { key: 'uris', title: 'software.sources.uris', role: 'meta', hideBelow: 'md' },
  { key: 'suites', title: 'software.sources.suites', role: 'meta', hideBelow: 'md' },
  { key: 'fingerprint', title: 'software.sources.fingerprint', role: 'meta', mono: true, hideBelow: 'sm' },
  { key: 'entry_count', title: 'software.sources.entries', role: 'meta', align: 'end' },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true, role: 'meta' },
  ...(session.canDelete ? [{ key: 'actions', title: 'common.actions', role: 'actions' as const }] : []),
]

onMounted(async () => {
  const save = resumeStepUp<PendingSave>(saveAction, 'list')
  const remove = resumeStepUp<PendingDelete>(deleteAction, 'list')
  if (!save && !remove) return
  await router.replace(withoutStepUpParam())
  if (save) {
    const code = save.failed ? 'step_up_failed' : ((await saveSoftwareSource(save.payload.id, save.payload.input, save.payload.keyChanged)) ?? '')
    if (code) await reopen(save.failed ? null : save.payload, code)
  } else if (remove) {
    pageProblem.value = remove.failed ? 'step_up_failed' : ((await deleteSoftwareSource(remove.payload.id)) ?? '')
  }
  await list.value?.reload()
})

async function loadTarget(id: string | null): Promise<boolean> {
  target.value = null
  if (!id) return true
  // The list carries no key; the edit form needs it to show what is in force.
  const full = await getSoftwareSource(id)
  if (typeof full === 'string') {
    pageProblem.value = full
    return false
  }
  target.value = full
  return true
}

async function openDialog(item: SoftwareSourceSummary | null): Promise<void> {
  pageProblem.value = ''
  draft.value = null
  draftProblem.value = ''
  if (!(await loadTarget(item?.id ?? null))) return
  formKey.value++
  open.value = true
}

/** Reopens the dialog after a refused save that ran after the step-up, with what was typed and the refusal at its field. */
async function reopen(payload: PendingSave | null, code: string): Promise<void> {
  if (!payload) {
    pageProblem.value = code
    return
  }
  if (!(await loadTarget(payload.id))) return
  draft.value = payload.input
  draftProblem.value = code
  formKey.value++
  open.value = true
}

function problemMessage(code: string): string {
  return code === 'in_use' ? t('software.sources.inUse') : problemText(code)
}

function onStepUp(input: SourceInput, keyChanged: boolean): void {
  startStepUp(saveAction, 'list', { id: target.value?.id ?? null, input, keyChanged } satisfies PendingSave)
}

async function onSaved(): Promise<void> {
  open.value = false
  await list.value?.reload()
}

async function remove(item: SoftwareSourceSummary): Promise<void> {
  pageProblem.value = ''
  const confirmed = await confirm({
    title: t('software.sources.deleteTitle'),
    message: t('software.sources.deleteConfirm'),
    confirmLabel: t('common.delete'),
    destructive: true,
    requireTypedText: item.name,
  })
  if (!confirmed) return
  const code = await deleteSoftwareSource(item.id)
  if (code === stepUpRequired) {
    startStepUp(deleteAction, 'list', { id: item.id } satisfies PendingDelete)
    return
  }
  pageProblem.value = code ?? ''
  await list.value?.reload()
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('software.sources.title') }}</h1>
      <v-btn
        v-if="session.canDelete"
        color="primary"
        data-testid="create-source"
        @click="openDialog(null)"
      >
        {{ t('software.sources.create') }}
      </v-btn>
    </div>
    <p class="summary">
      {{ t('software.sources.summary') }}
    </p>
    <p
      v-if="pageProblem"
      class="form-error"
      role="alert"
    >
      {{ problemMessage(pageProblem) }}
    </p>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listSoftwareSources"
      searchable
      default-sort="name"
      item-value="id"
      empty-icon="package"
      empty-title="software.sources.empty.title"
      empty-description="software.sources.empty.description"
      data-testid="source-list"
    >
      <template #[`item.uris`]="{ item }: { item: SoftwareSourceSummary }">
        <span class="mono">{{ item.uris.join(', ') }}</span>
      </template>
      <template #[`item.suites`]="{ item }: { item: SoftwareSourceSummary }">
        {{ item.suites.join(', ') }}
      </template>
      <template #[`item.fingerprint`]="{ item }: { item: SoftwareSourceSummary }">
        {{ groupFingerprint(item.fingerprint) }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: SoftwareSourceSummary }">
        <TimeCell :iso="item.updated_at" />
      </template>
      <template #[`item.actions`]="{ item }: { item: SoftwareSourceSummary }">
        <div class="row-actions">
          <v-btn
            :aria-label="t('managed.editLabel', { name: item.name })"
            variant="tonal"
            size="small"
            @click="openDialog(item)"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            :aria-label="t('managed.deleteLabel', { name: item.name })"
            color="error"
            size="small"
            :disabled="pending"
            @click="run(() => remove(item))"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </template>
    </DataList>

    <v-dialog
      v-model="open"
      max-width="48rem"
      :aria-label="target ? t('software.sources.editTitle') : t('software.sources.createTitle')"
    >
      <v-card :title="target ? t('software.sources.editTitle') : t('software.sources.createTitle')">
        <v-card-text>
          <SoftwareSourceForm
            :key="formKey"
            :initial="target"
            :draft="draft"
            :initial-problem="draftProblem"
            @saved="onSaved"
            @cancel="open = false"
            @step-up="onStepUp"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
