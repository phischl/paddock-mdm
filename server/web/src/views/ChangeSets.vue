<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import ChangeSetPlan from '../components/ChangeSetPlan.vue'
import ChangeSetRevertButton from '../components/ChangeSetRevertButton.vue'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { ChangeSet, ConfigApplyResult } from '../api/client'
import { changeSetFilters, getChangeSet, listChangeSets, revertChangeSet, revertDryRun } from '../lib/changeSets'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const router = useRouter()
const session = useSessionStore()
const problemText = useProblemText()
const selected = ref<ChangeSet | null>(null)
const list = ref<{ reload: () => Promise<void> } | null>(null)
const problem = ref('')
const reverted = ref('')
const revertTarget = ref<ChangeSet | null>(null)
const revertResult = ref<ConfigApplyResult | null>(null)
const planChanged = ref(false)
const nothingToRevert = ref(false)
const busy = ref(false)

// The step-up of a revert returns to this page; the pending revert names the change set to show the plan of again.
const stepUpAction = 'change-set-revert'
const stepUpTarget = 'change-sets'

const columns = computed<ListColumn[]>(() => [
  { key: 'applied_at', title: 'changeSets.appliedAt', sortable: true },
  { key: 'actor', title: 'changeSets.actor' },
  { key: 'source', title: 'changeSets.source' },
  { key: 'created', title: 'changeSets.created' },
  { key: 'updated', title: 'changeSets.updated' },
  { key: 'deleted', title: 'changeSets.deleted' },
  { key: 'actions', title: 'common.actions' },
])

onMounted(async () => {
  const pending = resumeStepUp<string>(stepUpAction, stepUpTarget)
  if (!pending) return
  await router.replace(withoutStepUpParam())
  if (pending.failed) {
    problem.value = 'step_up_failed'
    return
  }
  const cs = await getChangeSet(pending.payload)
  if (typeof cs === 'string') {
    problem.value = cs
    return
  }
  await startRevert(cs)
})

/** Opens a change set referenced by another one (reverts / reverted by). */
async function openChangeSet(id: string | null | undefined): Promise<void> {
  if (!id) return
  const cs = await getChangeSet(id)
  if (typeof cs === 'string') {
    problem.value = cs
    return
  }
  selected.value = cs
}

/**
 * Runs the dry run and shows the inverse plan for confirmation (plan M11 decision 22). A revert that needs a step-up
 * (a full profile) sends the browser through it first; the plan is shown again when it comes back.
 */
async function startRevert(cs: ChangeSet): Promise<void> {
  problem.value = ''
  reverted.value = ''
  nothingToRevert.value = false
  planChanged.value = false
  const res = await revertDryRun(cs.id)
  if (res === stepUpRequired) {
    startStepUp(stepUpAction, stepUpTarget, cs.id)
    return
  }
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  // An empty inverse plan has nothing to confirm: a revert would record no change set.
  if (res.plan.changes.length === 0) {
    nothingToRevert.value = true
    return
  }
  revertTarget.value = cs
  revertResult.value = res
}

function closeRevert(): void {
  revertTarget.value = null
  revertResult.value = null
  planChanged.value = false
}

/** Ignores a second confirmation while the first is under way, so a double click sends one revert. */
async function confirmRevert(): Promise<void> {
  if (busy.value) return
  busy.value = true
  try {
    await submitRevert()
  } finally {
    busy.value = false
  }
}

async function submitRevert(): Promise<void> {
  const cs = revertTarget.value
  const confirmed = revertResult.value
  if (!cs || !confirmed) return
  const res = await revertChangeSet(cs.id, confirmed.plan_sha256)
  if (res === 'plan_changed') {
    // The configuration changed since the dry run: the new plan replaces the shown one and must be confirmed again.
    const again = await revertDryRun(cs.id)
    // The new plan may touch a section that needs a step-up the first one did not.
    if (again === stepUpRequired) {
      startStepUp(stepUpAction, stepUpTarget, cs.id)
      return
    }
    if (typeof again === 'string') {
      closeRevert()
      problem.value = again
      return
    }
    if (again.plan.changes.length === 0) {
      closeRevert()
      nothingToRevert.value = true
      return
    }
    revertResult.value = again
    planChanged.value = true
    return
  }
  if (res === stepUpRequired) {
    startStepUp(stepUpAction, stepUpTarget, cs.id)
    return
  }
  closeRevert()
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  selected.value = null
  if (!res.change_set_id) {
    nothingToRevert.value = true
    return
  }
  reverted.value = formatDateTime(cs.applied_at, locale.value)
  await list.value?.reload()
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('changeSets.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('changeSets.summary') }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <v-alert
      v-if="reverted"
      type="success"
      variant="tonal"
      class="conflict"
      data-testid="change-set-reverted"
    >
      {{ t('changeSets.revert.done', { at: reverted }) }}
    </v-alert>
    <v-alert
      v-if="nothingToRevert"
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="change-set-nothing-to-revert"
    >
      {{ t('changeSets.revert.emptyPlan') }}
    </v-alert>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listChangeSets"
      :filters="changeSetFilters"
      searchable
      default-sort="-applied_at"
      item-value="id"
      empty-icon="diff"
      empty-title="changeSets.empty.title"
      empty-description="changeSets.empty.description"
      data-testid="change-set-list"
    >
      <template #[`item.applied_at`]="{ item }: { item: ChangeSet }">
        <TimeCell :iso="item.applied_at" />
      </template>
      <template #[`item.actor`]="{ item }: { item: ChangeSet }">
        {{ item.actor.display }}
      </template>
      <template #[`item.source`]="{ item }: { item: ChangeSet }">
        <StatusChip
          status="neutral"
          :label="t('changeSets.sources.' + item.source)"
        />
      </template>
      <template #[`item.created`]="{ item }: { item: ChangeSet }">
        {{ item.summary.created }}
      </template>
      <template #[`item.updated`]="{ item }: { item: ChangeSet }">
        {{ item.summary.updated }}
      </template>
      <template #[`item.deleted`]="{ item }: { item: ChangeSet }">
        {{ item.summary.deleted }}
      </template>
      <template #[`item.actions`]="{ item }: { item: ChangeSet }">
        <div class="row-actions">
          <v-btn
            size="small"
            variant="tonal"
            :aria-label="t('changeSets.detailsLabel', { at: formatDateTime(item.applied_at, locale) })"
            @click="selected = item"
          >
            {{ t('changeSets.details') }}
          </v-btn>
          <ChangeSetRevertButton
            v-if="session.canWrite"
            :change-set="item"
            :label="t('changeSets.revert.label', { at: formatDateTime(item.applied_at, locale) })"
            @revert="startRevert(item)"
          />
        </div>
      </template>
    </DataList>

    <v-dialog
      :model-value="!!selected"
      max-width="64rem"
      :aria-label="t('changeSets.detailsTitle')"
      @update:model-value="(v: boolean) => !v && (selected = null)"
    >
      <v-card
        v-if="selected"
        :title="t('changeSets.detailsTitle')"
      >
        <v-card-text>
          <p>
            {{ t('changeSets.detailsSummary', { actor: selected.actor.display, at: formatDateTime(selected.applied_at, locale) }) }}
          </p>
          <p v-if="selected.reverts_change_set_id">
            {{ t('changeSets.revertsLabel') }}
            <a
              href="#"
              data-testid="change-set-reverts"
              @click.prevent="openChangeSet(selected.reverts_change_set_id)"
            ><code>{{ selected.reverts_change_set_id }}</code></a>
          </p>
          <p v-if="selected.reverted_by">
            {{ t('changeSets.revertedByLabel') }}
            <a
              href="#"
              data-testid="change-set-reverted-by"
              @click.prevent="openChangeSet(selected.reverted_by)"
            ><code>{{ selected.reverted_by }}</code></a>
          </p>
          <ChangeSetPlan :plan="selected.plan" />
        </v-card-text>
        <v-card-actions>
          <ChangeSetRevertButton
            v-if="session.canWrite"
            :change-set="selected"
            :label="t('changeSets.revert.label', { at: formatDateTime(selected.applied_at, locale) })"
            @revert="startRevert(selected)"
          />
          <v-spacer />
          <v-btn
            color="primary"
            @click="selected = null"
          >
            {{ t('changeSets.close') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <ConfirmDialog
      v-if="revertTarget && revertResult"
      :model-value="true"
      :title="t('changeSets.revert.title')"
      :message="t('changeSets.revert.message', { at: formatDateTime(revertTarget.applied_at, locale) })"
      :confirm-label="t('changeSets.revert.action')"
      :warning="planChanged ? t('changeSets.revert.planChanged') : undefined"
      destructive
      @confirm="confirmRevert"
      @cancel="closeRevert"
    >
      <ChangeSetPlan :plan="revertResult.plan" />
    </ConfirmDialog>
  </section>
</template>
