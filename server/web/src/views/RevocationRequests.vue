<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import type { RevocationRequest } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { listRevocations, revocationFilters, reviewRevocation, reviewVerbs, type ReviewVerb } from '../lib/revocations'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The organization's revocation requests (plan M4c decision 18): a Destroy waits here for a second administrator, who
 * approves or rejects it after a step-up and with the typed hostname; its requester can cancel it.
 */
const { t, locale } = useI18n()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const fetch = listRevocations()
const problem = ref('')
const done = ref('')

const columns: ListColumn[] = [
  { key: 'hostname', title: 'revocations.hostname', sortable: true },
  { key: 'action', title: 'revocations.action', sortable: true },
  { key: 'status', title: 'revocations.status', sortable: true },
  { key: 'requested_at', title: 'revocations.requestedAt', sortable: true },
  { key: 'requested_by_username', title: 'revocations.requestedBy' },
  { key: 'reason', title: 'revocations.reason' },
  { key: 'actions', title: 'common.actions' },
]

/** The pending review of a step-up: the request and its hostname (no secret). */
interface Pending {
  id: string
  hostname: string
}

const stepUpAction = (verb: ReviewVerb) => 'revocation-' + verb

function start(verb: ReviewVerb, r: RevocationRequest): void {
  problem.value = ''
  done.value = ''
  startStepUp(stepUpAction(verb), 'revocation-requests', { id: r.id, hostname: r.hostname } satisfies Pending)
}

async function resume(): Promise<void> {
  for (const verb of ['approve', 'reject', 'cancel'] as ReviewVerb[]) {
    const resumed = resumeStepUp<Pending>(stepUpAction(verb), 'revocation-requests')
    if (!resumed) continue
    await router.replace(withoutStepUpParam())
    if (resumed.failed) {
      problem.value = 'step_up_failed'
      return
    }
    await review(verb, resumed.payload)
    return
  }
}

async function review(verb: ReviewVerb, p: Pending): Promise<void> {
  const key = 'revocations.review.' + verb
  const confirmed = await confirm({
    title: t(key + '.title'), message: t(key + '.confirm', { hostname: p.hostname }), confirmLabel: t(key + '.label'),
    destructive: verb === 'approve', requireTypedText: p.hostname,
  })
  if (!confirmed) return
  const res = await reviewRevocation(p.id, verb, p.hostname)
  if (res) {
    problem.value = res
    return
  }
  done.value = t(key + '.done', { hostname: p.hostname })
  await list.value?.reload()
}

onMounted(resume)
</script>

<template>
  <section class="page">
    <h1>{{ t('revocations.title') }}</h1>
    <v-alert
      v-if="!session.me?.revocation_enabled"
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="revocation-disabled"
    >
      {{ t('revocations.disabled') }}
    </v-alert>
    <p class="summary">
      {{ t('revocations.hint') }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <p
      v-if="done"
      role="status"
      data-testid="revocation-reviewed"
    >
      {{ done }}
    </p>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="fetch"
      :filters="revocationFilters"
      searchable
      default-sort="-requested_at"
      item-value="id"
      data-testid="revocation-list"
    >
      <template #[`item.hostname`]="{ item }: { item: RevocationRequest }">
        <RouterLink :to="{ name: 'device', params: { id: item.device_id } }">
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.action`]="{ item }: { item: RevocationRequest }">
        {{ t('revocations.actions.' + item.action) }}
      </template>
      <template #[`item.status`]="{ item }: { item: RevocationRequest }">
        {{ t('revocations.statuses.' + item.status) }}
        <span v-if="item.rejection">({{ item.rejection }})</span>
      </template>
      <template #[`item.requested_at`]="{ item }: { item: RevocationRequest }">
        {{ formatDateTime(item.requested_at, locale) }}
      </template>
      <template #[`item.requested_by_username`]="{ item }: { item: RevocationRequest }">
        {{ item.requested_by_username ?? t('revocations.deadMansSwitch') }}
      </template>
      <template #[`item.actions`]="{ item }: { item: RevocationRequest }">
        <div class="row-actions">
          <v-btn
            v-for="verb in reviewVerbs(item, session.me?.id)"
            :key="verb"
            size="small"
            :color="verb === 'approve' ? 'error' : undefined"
            :variant="verb === 'approve' ? 'flat' : 'outlined'"
            :data-testid="'revocation-' + verb"
            @click="start(verb, item)"
          >
            {{ t('revocations.review.' + verb + '.label') }}
          </v-btn>
        </div>
      </template>
    </DataList>
  </section>
</template>
