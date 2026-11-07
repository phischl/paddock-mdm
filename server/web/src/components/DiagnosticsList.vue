<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import DataList from './DataList.vue'
import StatusChip from './StatusChip.vue'
import TimeCell from './TimeCell.vue'
import type { Diagnostics } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { diagnosticsStateFilter, diagnosticsStateView, downloadDiagnostics, purgeDiagnostics } from '../lib/diagnostics'
import { saveFile } from '../lib/disk'
import { formatMiB } from '../lib/format'
import type { ListColumn, ListParams, Page } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The diagnostics bundles of a device or of the organization (ADR 0048, plan M12 decision 14), for administrators and
 * operators: a download runs the step-up flow when the server asks for it (every download is audited and may name
 * the device's users), the purge is the administrator's and is confirmed in a dialog.
 */
const props = defineProps<{
  fetch: (params: ListParams) => Promise<Page<Diagnostics>>
  /** The fleet page shows and searches the hostname; the device tab does not. */
  fleet?: boolean
}>()

const { t, locale } = useI18n()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const problem = ref('')
const busy = ref('')

const stepUpAction = 'diagnostics-download'
const stepUpTarget = 'diagnostics'

const columns = computed<ListColumn[]>(() => [
  ...(props.fleet ? [{ key: 'hostname', title: 'diagnostics.hostname', sortable: true }] : []),
  { key: 'requested_at', title: 'diagnostics.requestedAt', sortable: true },
  { key: 'requested_by', title: 'diagnostics.requestedBy' },
  { key: 'reason', title: 'diagnostics.reason' },
  { key: 'state', title: 'diagnostics.state', sortable: true, role: 'status' },
  { key: 'size', title: 'diagnostics.size' },
  { key: 'download_count', title: 'diagnostics.downloads' },
  { key: 'expires_at', title: 'diagnostics.expiresAt' },
  { key: 'actions', title: 'common.actions', role: 'actions' },
])

/** Reloads the list, e.g. after a request. */
defineExpose({ reload: () => list.value?.reload() })

onMounted(async () => {
  const resumed = resumeStepUp<string>(stepUpAction, stepUpTarget)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  await download(resumed.payload, false)
})

async function download(id: string, stepUp: boolean): Promise<void> {
  problem.value = ''
  busy.value = id
  const res = await downloadDiagnostics(id)
  busy.value = ''
  if (typeof res === 'string') {
    if (res === stepUpRequired && stepUp) {
      startStepUp(stepUpAction, stepUpTarget, id)
      return
    }
    problem.value = res
    void list.value?.reload()
    return
  }
  saveFile(res)
  void list.value?.reload()
}

async function purge(item: Diagnostics): Promise<void> {
  problem.value = ''
  const confirmed = await confirm({
    title: t('diagnostics.purge.title'),
    message: t('diagnostics.purge.confirm', { hostname: item.hostname }),
    confirmLabel: t('diagnostics.purge.label'),
    destructive: true,
  })
  if (!confirmed) return
  problem.value = (await purgeDiagnostics(item.id)) ?? ''
  void list.value?.reload()
}
</script>

<template>
  <div>
    <v-alert
      v-if="problem"
      type="error"
      variant="tonal"
      role="alert"
      data-testid="diagnostics-problem"
    >
      {{ problemText(problem) }}
    </v-alert>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="props.fetch"
      :filters="[diagnosticsStateFilter]"
      :searchable="fleet"
      default-sort="-requested_at"
      item-value="id"
      :query-prefix="fleet ? undefined : 'd'"
      empty-icon="file-check"
      empty-title="diagnostics.empty.title"
      empty-description="diagnostics.empty.description"
      data-testid="diagnostics-list"
    >
      <template #[`item.hostname`]="{ item }: { item: Diagnostics }">
        <RouterLink :to="{ name: 'device-diagnostics', params: { id: item.device_id } }">
          {{ item.hostname }}
        </RouterLink>
      </template>
      <template #[`item.requested_at`]="{ item }: { item: Diagnostics }">
        <TimeCell :iso="item.requested_at" />
      </template>
      <template #[`item.reason`]="{ item }: { item: Diagnostics }">
        {{ item.reason }}
      </template>
      <template #[`item.state`]="{ item }: { item: Diagnostics }">
        <StatusChip
          :status="diagnosticsStateView(item.state).status"
          :label="t(diagnosticsStateView(item.state).label)"
          :title="item.failed_reason ? t('diagnostics.failedReason', { reason: item.failed_reason }) : undefined"
          :data-testid="'diagnostics-state-' + item.state"
        />
        <StatusChip
          v-if="item.notified_sessions === 0"
          class="ms-1"
          status="warn"
          :label="t('diagnostics.notNotified')"
          :title="t('diagnostics.notNotifiedHint')"
          data-testid="diagnostics-not-notified"
        />
      </template>
      <template #[`item.size`]="{ item }: { item: Diagnostics }">
        <template v-if="item.size">
          {{ formatMiB(item.size, locale, Math.ceil) }}
        </template>
      </template>
      <template #[`item.expires_at`]="{ item }: { item: Diagnostics }">
        <TimeCell
          v-if="item.state === 'stored' && item.expires_at"
          :iso="item.expires_at"
        />
      </template>
      <template #[`item.actions`]="{ item }: { item: Diagnostics }">
        <template v-if="item.state === 'stored'">
          <v-btn
            size="small"
            variant="tonal"
            :loading="busy === item.id"
            :aria-label="t('diagnostics.downloadLabel', { hostname: item.hostname })"
            data-testid="diagnostics-download"
            @click="download(item.id, true)"
          >
            {{ t('diagnostics.download') }}
          </v-btn>
          <v-btn
            v-if="session.canDelete"
            size="small"
            color="error"
            :aria-label="t('diagnostics.purge.ariaLabel', { hostname: item.hostname })"
            data-testid="diagnostics-purge"
            @click="purge(item)"
          >
            {{ t('diagnostics.purge.label') }}
          </v-btn>
        </template>
      </template>
    </DataList>
  </div>
</template>
