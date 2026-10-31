<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { AuditEvidenceKey, AuditExport } from '../api/client'
import ActorChip from '../components/ActorChip.vue'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import {
  chainStatus, createAuditExport, defaultRange, downloadUrl, exportFilters, exportStatus, formatSize, hasOpenExport, listAuditExports,
  listAuditKeys, validateExport,
} from '../lib/auditExports'
import { formatDateTime } from '../lib/format'
import type { ListColumn, ListParams, Page } from '../lib/listQuery'
import { reducedMotion } from '../lib/pageContext'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'

/**
 * Evidence exports (plan M10 decision 37): the signed packages of the audit log an auditor requests, follows and
 * downloads, and the signing key fingerprints to compare with an independently recorded value. A request needs a
 * step-up: the dialog starts it and the request is posted when the browser comes back.
 */
const { t, locale } = useI18n()
const router = useRouter()
const problemText = useProblemText()
const dialogId = useId()

const stepUpAction = 'audit-export'
const stepUpTarget = 'exports'
/** Seconds between two refreshes while the audit writer still builds an export. */
const followSeconds = 10

interface Request {
  from: string
  to: string
  purpose: string
}

const list = ref<{ reload: () => Promise<void> } | null>(null)
const dialog = ref(false)
const range = defaultRange(new Date())
const from = ref(range.from)
const to = ref(range.to)
const purpose = ref('')
const errors = ref<Record<string, string>>({})
const problem = ref('')
const requested = ref(false)
const keys = ref<AuditEvidenceKey[]>([])
const keysProblem = ref('')
const keysLoaded = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined
let open = false
let gone = false

const columns: ListColumn[] = [
  { key: 'requested_at', title: 'auditExports.requestedAt', sortable: true, role: 'meta' },
  { key: 'from_day', title: 'auditExports.range', sortable: true, role: 'primary', mono: true },
  { key: 'status', title: 'auditExports.status', sortable: true, role: 'status' },
  { key: 'purpose', title: 'auditExports.purpose', role: 'meta', hideBelow: 'sm' },
  { key: 'requested_by', title: 'auditExports.requestedBy', role: 'meta', hideBelow: 'md' },
  { key: 'size', title: 'auditExports.size', role: 'meta', align: 'end', hideBelow: 'md' },
  { key: 'verify_ok', title: 'auditExports.chain.title', role: 'meta' },
  { key: 'actions', title: 'common.actions' },
]

const rangeText = (e: AuditExport) => (e.from_day === e.to_day ? e.from_day : e.from_day + ' – ' + e.to_day)

function follow(): void {
  clearTimeout(timer)
  if (gone || !open) return
  timer = setTimeout(async () => {
    await list.value?.reload()
    follow()
  }, followSeconds * 1000)
}

async function fetchExports(p: ListParams): Promise<Page<AuditExport>> {
  const page = await listAuditExports(p)
  open = hasOpenExport(page.items)
  follow()
  return page
}

function openDialog(): void {
  problem.value = ''
  errors.value = {}
  requested.value = false
  dialog.value = true
}

function submit(): void {
  errors.value = validateExport(from.value, to.value, purpose.value)
  if (Object.keys(errors.value).length > 0) return
  const body: Request = { from: from.value, to: to.value, purpose: purpose.value.trim() }
  startStepUp(stepUpAction, stepUpTarget, body)
}

async function post(body: Request): Promise<void> {
  const res = await createAuditExport({ from_day: body.from, to_day: body.to, purpose: body.purpose })
  if (typeof res === 'string') {
    from.value = body.from
    to.value = body.to
    purpose.value = body.purpose
    problem.value = res
    dialog.value = true
    return
  }
  requested.value = true
  await list.value?.reload()
}

async function resume(): Promise<void> {
  const resumed = resumeStepUp<Request>(stepUpAction, stepUpTarget)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  await post(resumed.payload)
}

const bytes = (e: AuditExport) => (e.size === null ? '–' : formatSize(e.size, locale.value))
const at = (iso: string | null) => (iso ? formatDateTime(iso, locale.value) : '–')
const hasKeys = computed(() => keys.value.length > 0)

onMounted(async () => {
  const k = await listAuditKeys()
  if (typeof k === 'string') keysProblem.value = k
  else keys.value = k
  keysLoaded.value = true
  await nextTick()
  await resume()
})

onBeforeUnmount(() => {
  gone = true
  clearTimeout(timer)
})
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('auditExports.title') }}</h1>
      <v-btn
        color="primary"
        data-testid="new-export"
        @click="openDialog"
      >
        {{ t('auditExports.new') }}
      </v-btn>
    </div>
    <p class="pd-muted">
      {{ t('auditExports.intro') }}
    </p>
    <p
      v-if="problem && !dialog"
      class="form-error"
      role="alert"
      data-testid="export-problem"
    >
      {{ problemText(problem) }}
    </p>
    <p
      v-if="requested"
      role="status"
      data-testid="export-requested"
    >
      {{ t('auditExports.requested') }}
    </p>

    <DataList
      ref="list"
      :columns="columns"
      :fetch="fetchExports"
      :filters="exportFilters"
      searchable
      expandable
      default-sort="-requested_at"
      item-value="id"
      empty-icon="file-check"
      empty-title="auditExports.empty.title"
      empty-description="auditExports.empty.description"
      data-testid="audit-exports"
    >
      <template #[`item.requested_at`]="{ item }: { item: AuditExport }">
        <TimeCell :iso="item.requested_at" />
      </template>
      <template #[`item.from_day`]="{ item }: { item: AuditExport }">
        <span class="mono">{{ rangeText(item) }}</span>
      </template>
      <template #[`item.status`]="{ item }: { item: AuditExport }">
        <StatusChip
          class="export-status"
          :status="exportStatus(item.status).status"
          :label="t(exportStatus(item.status).label)"
        />
        <p
          v-if="item.status === 'failed' && item.error"
          class="export-error"
        >
          {{ item.error }}
        </p>
      </template>
      <template #[`item.purpose`]="{ item }: { item: AuditExport }">
        <span class="export-purpose">{{ item.purpose }}</span>
      </template>
      <template #[`item.requested_by`]="{ item }: { item: AuditExport }">
        <ActorChip
          :actor="item.requested_by"
          source="portal"
        />
      </template>
      <template #[`item.size`]="{ item }: { item: AuditExport }">
        {{ bytes(item) }}
      </template>
      <template #[`item.verify_ok`]="{ item }: { item: AuditExport }">
        <StatusChip
          v-if="chainStatus(item.verify_ok)"
          class="export-chain"
          :status="chainStatus(item.verify_ok)!.status"
          :label="t(chainStatus(item.verify_ok)!.label)"
          :title="item.verify_problems.join('\n') || undefined"
        />
        <span
          v-else
          class="pd-muted"
        >–</span>
      </template>
      <template #[`item.actions`]="{ item }: { item: AuditExport }">
        <a
          v-if="item.status === 'ready'"
          class="export-download"
          :href="downloadUrl(item.id)"
          download
        >{{ t('auditExports.download') }}</a>
      </template>
      <template #expanded="{ item }: { item: AuditExport }">
        <dl class="export-details">
          <dt>{{ t('auditExports.purpose') }}</dt>
          <dd class="export-purpose">
            {{ item.purpose }}
          </dd>
          <template v-if="item.status === 'ready' || item.status === 'expired'">
            <dt>{{ t('auditExports.sha256') }}</dt>
            <dd class="mono">
              {{ item.package_sha256 ?? '–' }}
            </dd>
            <dt>{{ t('auditExports.counts') }}</dt>
            <dd>{{ t('auditExports.countsValue', { events: item.event_count ?? 0, objects: item.object_count ?? 0 }) }}</dd>
            <dt>{{ t('auditExports.keyVersion') }}</dt>
            <dd>{{ item.key_version ?? '–' }}</dd>
            <dt>{{ t('auditExports.expiresAt') }}</dt>
            <dd>{{ at(item.expires_at) }}</dd>
          </template>
          <template v-if="item.verify_problems.length > 0">
            <dt>{{ t('auditExports.chain.problems') }}</dt>
            <dd>
              <ul data-testid="export-problems">
                <li
                  v-for="(p, i) in item.verify_problems"
                  :key="i"
                  class="mono"
                >
                  {{ p }}
                </li>
              </ul>
            </dd>
          </template>
          <template v-if="item.error">
            <dt>{{ t('auditExports.error') }}</dt>
            <dd>{{ item.error }}</dd>
          </template>
        </dl>
      </template>
    </DataList>

    <v-card
      class="keys-card"
      variant="outlined"
      data-testid="audit-keys"
    >
      <v-card-title
        tag="h2"
        class="keys-title"
      >
        {{ t('auditExports.keys.title') }}
      </v-card-title>
      <v-card-text>
        <p class="pd-muted">
          {{ t('auditExports.keys.hint') }}
        </p>
        <p
          v-if="keysProblem"
          class="form-error"
          role="alert"
        >
          {{ problemText(keysProblem) }}
        </p>
        <p
          v-else-if="keysLoaded && !hasKeys"
          class="pd-muted"
        >
          {{ t('auditExports.keys.none') }}
        </p>
        <table
          v-else-if="hasKeys"
          class="keys-table"
        >
          <caption class="visually-hidden">
            {{ t('auditExports.keys.title') }}
          </caption>
          <thead>
            <tr>
              <th scope="col">
                {{ t('auditExports.keys.version') }}
              </th>
              <th scope="col">
                {{ t('auditExports.keys.fingerprint') }}
              </th>
              <th scope="col">
                {{ t('auditExports.keys.firstSeen') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="k in keys"
              :key="k.key_version"
              data-testid="audit-key"
            >
              <td>{{ k.key_version }}</td>
              <td class="mono key-fingerprint">
                {{ k.fingerprint }}
              </td>
              <td>{{ at(k.first_seen_at) }}</td>
            </tr>
          </tbody>
        </table>
      </v-card-text>
    </v-card>

    <v-dialog
      v-model="dialog"
      max-width="560"
      :transition="reducedMotion() ? false : 'dialog-transition'"
      :aria-labelledby="dialogId + '-title'"
    >
      <v-card data-testid="export-dialog">
        <v-card-title
          :id="dialogId + '-title'"
          tag="h2"
          class="confirm-title"
        >
          {{ t('auditExports.dialog.title') }}
        </v-card-title>
        <v-card-text>
          <p>{{ t('auditExports.dialog.explanation') }}</p>
          <v-text-field
            v-model="from"
            :label="t('auditExports.dialog.from')"
            type="date"
            :error-messages="errors.from ? [t(errors.from)] : []"
            data-testid="export-from"
          />
          <v-text-field
            v-model="to"
            :label="t('auditExports.dialog.to')"
            type="date"
            :error-messages="errors.to ? [t(errors.to)] : []"
            data-testid="export-to"
          />
          <v-textarea
            v-model="purpose"
            :label="t('auditExports.purpose')"
            :hint="t('auditExports.dialog.purposeHint')"
            persistent-hint
            :counter="500"
            :maxlength="500"
            rows="3"
            auto-grow
            autocomplete="off"
            :error-messages="errors.purpose ? [t(errors.purpose)] : []"
            data-testid="export-purpose"
          />
          <p
            v-if="problem"
            class="form-error"
            role="alert"
            data-testid="export-dialog-problem"
          >
            {{ problemText(problem) }}
          </p>
          <div class="form-actions">
            <v-btn
              variant="tonal"
              data-testid="export-cancel"
              @click="dialog = false"
            >
              {{ t('common.cancel') }}
            </v-btn>
            <v-btn
              color="primary"
              variant="flat"
              data-testid="export-submit"
              @click="submit"
            >
              {{ t('auditExports.dialog.submit') }}
            </v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>

<style scoped>
.export-purpose {
  white-space: pre-line;
  overflow-wrap: anywhere;
}
.export-error {
  margin: 0.25rem 0 0;
}
.export-details {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.25rem 1rem;
  margin: 0;
}
.keys-card {
  margin-top: 1.5rem;
}
.keys-table {
  border-collapse: collapse;
}
.keys-table th,
.keys-table td {
  text-align: start;
  padding: 0.25rem 1rem 0.25rem 0;
}
.key-fingerprint {
  overflow-wrap: anywhere;
}
</style>
