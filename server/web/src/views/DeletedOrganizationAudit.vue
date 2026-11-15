<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { AuditExport, Organization } from '../api/client'
import AuditEventList from '../components/AuditEventList.vue'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import { chainStatus, defaultRange, exportFilters, exportStatus, formatSize, hasOpenExport, validateExport } from '../lib/auditExports'
import { formatDateTime } from '../lib/format'
import type { ListColumn, ListParams, Page } from '../lib/listQuery'
import {
  createDeletedOrganizationAuditExport, deletedOrganizationExportUrl, getOrganization, listDeletedOrganizationAuditEvents,
  listDeletedOrganizationAuditExports,
} from '../lib/organizations'
import { reducedMotion } from '../lib/pageContext'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'

/**
 * The retained audit of a deleted organization (plan M17, ADR 0052 decision 7): the outcome of the final chain
 * verification, the audit log and the signed evidence exports. A failed verification is shown as an error because
 * the retained evidence then did not verify. Requesting an export needs a step-up.
 */
const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const problemText = useProblemText()
const dialogId = useId()

const id = computed(() => String(route.params.id))
const stepUpAction = 'organization-audit-export'
const stepUpTarget = 'exports'
const followSeconds = 10

interface Request {
  from: string
  to: string
  purpose: string
}

const org = ref<Organization | null>(null)
const loadProblem = ref('')
const list = ref<{ reload: () => Promise<void> } | null>(null)
const dialog = ref(false)
const range = defaultRange(new Date())
const from = ref(range.from)
const to = ref(range.to)
const purpose = ref('')
const errors = ref<Record<string, string>>({})
const problem = ref('')
const requested = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined
let open = false
let gone = false

const events = computed(() => listDeletedOrganizationAuditEvents(id.value))
const exportsFetch = computed(() => listDeletedOrganizationAuditExports(id.value))
const finalOutcome = computed(() => org.value?.deletion?.audit_final_outcome ?? null)
const finalAt = computed(() => (org.value?.deletion?.audit_final_verified_at ? formatDateTime(org.value.deletion.audit_final_verified_at, locale.value) : ''))

const columns: ListColumn[] = [
  { key: 'requested_at', title: 'auditExports.requestedAt', sortable: true, role: 'meta' },
  { key: 'from_day', title: 'auditExports.range', sortable: true, role: 'primary', mono: true },
  { key: 'status', title: 'auditExports.status', sortable: true, role: 'status' },
  { key: 'size', title: 'auditExports.size', role: 'meta', align: 'end', hideBelow: 'md' },
  { key: 'verify_ok', title: 'auditExports.chain.title', role: 'meta' },
  { key: 'actions', title: 'common.actions' },
]

const rangeText = (e: AuditExport) => (e.from_day === e.to_day ? e.from_day : e.from_day + ' – ' + e.to_day)
const bytes = (e: AuditExport) => (e.size === null ? '–' : formatSize(e.size, locale.value))

function follow(): void {
  clearTimeout(timer)
  if (gone || !open) return
  timer = setTimeout(async () => {
    await list.value?.reload()
    follow()
  }, followSeconds * 1000)
}

async function fetchExports(p: ListParams): Promise<Page<AuditExport>> {
  const page = await exportsFetch.value(p)
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
  startStepUp(stepUpAction, stepUpTarget, { from: from.value, to: to.value, purpose: purpose.value.trim() } satisfies Request)
}

async function post(body: Request, stepUp: boolean): Promise<void> {
  const res = await createDeletedOrganizationAuditExport(id.value, { from_day: body.from, to_day: body.to, purpose: body.purpose })
  if (res === stepUpRequired && stepUp) {
    startStepUp(stepUpAction, stepUpTarget, body)
    return
  }
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
  await post(resumed.payload, false)
}

onMounted(async () => {
  const res = await getOrganization(id.value)
  if (typeof res === 'string') loadProblem.value = res
  else org.value = res
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
      <h1>{{ t('organizations.audit.title', { name: org?.name ?? '' }) }}</h1>
      <v-btn
        :to="{ name: 'organizations' }"
        variant="tonal"
      >
        {{ t('organizations.audit.back') }}
      </v-btn>
    </div>
    <p
      v-if="loadProblem"
      class="form-error"
      role="alert"
    >
      {{ problemText(loadProblem) }}
    </p>
    <template v-if="org">
      <p class="pd-muted">
        {{ t('organizations.audit.intro', { slug: org.slug }) }}
      </p>
      <v-alert
        v-if="finalOutcome === 'failed'"
        type="error"
        variant="flat"
        role="alert"
        data-testid="audit-final-failed"
      >
        {{ t('organizations.audit.finalFailed', { date: finalAt }) }}
      </v-alert>
      <v-alert
        v-else-if="finalOutcome === 'verified'"
        type="success"
        variant="tonal"
        data-testid="audit-final-verified"
      >
        {{ t('organizations.audit.finalVerified', { date: finalAt }) }}
      </v-alert>
      <p
        v-else
        class="pd-muted"
        data-testid="audit-final-none"
      >
        {{ t('organizations.audit.finalNone') }}
      </p>

      <h2>{{ t('organizations.audit.logTitle') }}</h2>
      <AuditEventList
        :fetch="events"
        :show-device="false"
        data-testid="deleted-organization-audit"
      />

      <div class="page-header">
        <h2>{{ t('auditExports.title') }}</h2>
        <v-btn
          color="primary"
          data-testid="new-export"
          @click="openDialog"
        >
          {{ t('auditExports.new') }}
        </v-btn>
      </div>
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
        default-sort="-requested_at"
        item-value="id"
        empty-icon="file-check"
        empty-title="auditExports.empty.title"
        empty-description="auditExports.empty.description"
        data-testid="deleted-organization-exports"
      >
        <template #[`item.requested_at`]="{ item }: { item: AuditExport }">
          <TimeCell :iso="item.requested_at" />
        </template>
        <template #[`item.from_day`]="{ item }: { item: AuditExport }">
          <span class="mono">{{ rangeText(item) }}</span>
        </template>
        <template #[`item.status`]="{ item }: { item: AuditExport }">
          <StatusChip
            :status="exportStatus(item.status).status"
            :label="t(exportStatus(item.status).label)"
          />
        </template>
        <template #[`item.size`]="{ item }: { item: AuditExport }">
          {{ bytes(item) }}
        </template>
        <template #[`item.verify_ok`]="{ item }: { item: AuditExport }">
          <StatusChip
            v-if="chainStatus(item.verify_ok)"
            :status="chainStatus(item.verify_ok)!.status"
            :label="t(chainStatus(item.verify_ok)!.label)"
          />
          <span
            v-else
            class="pd-muted"
          >–</span>
        </template>
        <template #[`item.actions`]="{ item }: { item: AuditExport }">
          <a
            v-if="item.status === 'ready'"
            :href="deletedOrganizationExportUrl(id, item.id)"
            download
            :data-testid="'export-download-' + item.id"
          >{{ t('auditExports.download') }}</a>
        </template>
      </DataList>
    </template>

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
