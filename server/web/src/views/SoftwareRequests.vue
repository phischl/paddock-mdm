<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { SoftwareRequest } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import {
  canDecide, decideSoftwareRequest, decisionReasonMax, listSoftwareRequests, softwareRequestFilters, softwareRequestStatus,
} from '../lib/softwareRequests'
import { useSessionStore } from '../stores/session'

/**
 * The users' requests for applications that need approval (plan M13c decision 10). An organization administrator
 * approves an open request, optionally with a reason, or denies it with a reason the user sees; operators and auditors
 * read the list. The user's justification and the decision's reason are untrusted plain text and render as text only.
 */
const { t } = useI18n()
const { pending, run } = usePending()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const problem = ref('')
const done = ref('')

const columns = computed<ListColumn[]>(() => [
  { key: 'entry_name', title: 'softwareRequests.application', role: 'primary' },
  { key: 'username', title: 'softwareRequests.user', sortable: true, role: 'meta' },
  { key: 'hostname', title: 'devices.hostname', role: 'meta' },
  { key: 'state', title: 'softwareRequests.state', sortable: true, role: 'status' },
  { key: 'requested_at', title: 'softwareRequests.requestedAt', sortable: true, role: 'meta' },
  { key: 'expires_at', title: 'softwareRequests.expiresAt', sortable: true, role: 'meta', hideBelow: 'md' },
  { key: 'justification', title: 'softwareRequests.justification', role: 'meta', hideBelow: 'md' },
  { key: 'decision', title: 'softwareRequests.decision', role: 'meta', hideBelow: 'md' },
  ...(session.canDelete ? [{ key: 'actions', title: 'common.actions', role: 'actions' as const }] : []),
])

async function decide(verb: 'approve' | 'deny', r: SoftwareRequest): Promise<void> {
  problem.value = ''
  done.value = ''
  const key = 'softwareRequests.' + verb
  const answer = await confirm({
    title: t(key + '.title'),
    message: t(key + '.confirm', { app: r.entry_name, user: r.username, hostname: r.hostname }),
    confirmLabel: t(key + '.label'),
    destructive: verb === 'deny',
    reason: {
      label: t(key + '.reason'), hint: t(key + '.reasonHint'), required: verb === 'deny', maxLength: decisionReasonMax,
    },
  })
  if (answer === false) return
  const code = await decideSoftwareRequest(r.id, verb, answer.reason)
  if (code) {
    problem.value = code
  } else {
    done.value = t(key + '.done', { app: r.entry_name, user: r.username })
  }
  await list.value?.reload()
}
</script>

<template>
  <section class="page">
    <h1>{{ t('softwareRequests.title') }}</h1>
    <p class="summary">
      {{ t('softwareRequests.summary') }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
      data-testid="request-problem"
    >
      {{ problemText(problem) }}
    </p>
    <p
      v-if="done"
      role="status"
      data-testid="request-done"
    >
      {{ done }}
    </p>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listSoftwareRequests"
      :filters="softwareRequestFilters"
      searchable
      default-sort="-requested_at"
      item-value="id"
      empty-icon="package"
      empty-title="softwareRequests.empty.title"
      empty-description="softwareRequests.empty.description"
      data-testid="software-request-list"
    >
      <template #[`item.entry_name`]="{ item }: { item: SoftwareRequest }">
        <RouterLink :to="{ name: 'software-catalog-entry', params: { id: item.catalog_entry_id } }">
          {{ item.entry_name }}
        </RouterLink>
      </template>
      <template #[`item.hostname`]="{ item }: { item: SoftwareRequest }">
        <RouterLink :to="{ name: 'device', params: { id: item.device_id } }">
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.state`]="{ item }: { item: SoftwareRequest }">
        <StatusChip
          :status="softwareRequestStatus(item.state).status"
          :label="t(softwareRequestStatus(item.state).label)"
          data-testid="request-state"
        />
      </template>
      <template #[`item.requested_at`]="{ item }: { item: SoftwareRequest }">
        <TimeCell
          :iso="item.requested_at"
          mode="relative"
        />
      </template>
      <template #[`item.expires_at`]="{ item }: { item: SoftwareRequest }">
        <TimeCell
          v-if="item.state === 'requested'"
          :iso="item.expires_at"
        />
        <span
          v-else
          class="pd-muted"
        >–</span>
      </template>
      <template #[`item.justification`]="{ item }: { item: SoftwareRequest }">
        <!-- Untrusted text from the user's device (maintainer answer Q7): text interpolation only, never v-html. -->
        <span
          v-if="item.justification"
          class="request-text"
          dir="auto"
          data-testid="request-justification"
        >{{ item.justification }}</span>
        <span
          v-else
          class="pd-muted"
        >–</span>
      </template>
      <template #[`item.decision`]="{ item }: { item: SoftwareRequest }">
        <span
          v-if="item.decided_at"
          data-testid="request-decision"
        >
          <span v-if="item.decided_by">{{ t('softwareRequests.decidedBy', { name: item.decided_by }) }}</span>
          <TimeCell :iso="item.decided_at" />
          <span
            v-if="item.decision_reason"
            class="decision-reason"
          >{{ item.decision_reason }}</span>
        </span>
        <span
          v-else
          class="pd-muted"
        >–</span>
      </template>
      <template #[`item.actions`]="{ item }: { item: SoftwareRequest }">
        <div
          v-if="canDecide(item, session.canDelete)"
          class="row-actions"
        >
          <v-btn
            :aria-label="t('softwareRequests.approve.aria', { app: item.entry_name, user: item.username })"
            variant="tonal"
            size="small"
            :disabled="pending"
            data-testid="approve-request"
            @click="run(() => decide('approve', item))"
          >
            {{ t('softwareRequests.approve.label') }}
          </v-btn>
          <v-btn
            :aria-label="t('softwareRequests.deny.aria', { app: item.entry_name, user: item.username })"
            color="error"
            size="small"
            :disabled="pending"
            data-testid="deny-request"
            @click="run(() => decide('deny', item))"
          >
            {{ t('softwareRequests.deny.label') }}
          </v-btn>
        </div>
      </template>
    </DataList>
  </section>
</template>

<style scoped>
.request-text {
  unicode-bidi: isolate;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.decision-reason {
  display: block;
  white-space: pre-wrap;
  color: var(--pd-text-muted);
}
</style>
