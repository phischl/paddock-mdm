<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import SetupChecklist from '../components/SetupChecklist.vue'
import UpgradeCard from '../components/UpgradeCard.vue'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import OrganizationDeleteDialog from '../components/OrganizationDeleteDialog.vue'
import type { Organization } from '../api/client'
import {
  cancelOrganizationDeletion, canRequestDeletion, createOrganization, deletionPending, listOrganizations, organizationFilters,
  requestOrganizationDeletion, updateOrganizationDomains, type OrganizationDeletionInput,
} from '../lib/organizations'
import { useConfirm } from '../composables/useConfirm'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { hasErrors, parseDomains, validateDomains, validateOrganization } from '../lib/validation'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { formatDateTime } from '../lib/format'
import { organizationStatus } from '../lib/status'
import { usePending } from '../composables/usePending'

const { t, te, locale } = useI18n()
const confirm = useConfirm()
const router = useRouter()
const { pending, run } = usePending()
const problemText = useProblemText()
const list = ref<{ reload: () => Promise<void> } | null>(null)

const open = ref(false)
const slug = ref('')
const name = ref('')
const domains = ref('')
const touched = ref(false)
const problem = ref('')
// Set when the organization exists but the PATCH of its domains failed (plan M8x decision 21).
const domainsNotSaved = ref(false)
// The create waits for the identity provider setup, bounded at 60 s (app.ProvisioningBudget, PDK-407).
const provisioning = ref(false)
const errors = computed(() => validateOrganization(slug.value, name.value))
const slugError = computed(() => (touched.value && errors.value.slug ? t(errors.value.slug) : ''))
const nameError = computed(() => (touched.value && errors.value.name ? t(errors.value.name) : ''))
const domainsError = computed(() => {
  const key = validateDomains(domains.value)
  return touched.value && key ? t(key) : ''
})

// The domains dialog of one row.
const editing = ref<Organization | null>(null)
const editDomains = ref('')
const editTouched = ref(false)
const editProblem = ref('')
const editError = computed(() => {
  const key = validateDomains(editDomains.value)
  return editTouched.value && key ? t(key) : ''
})

const columns: ListColumn[] = [
  { key: 'slug', title: 'organizations.slug', sortable: true },
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'domains', title: 'organizations.editDomains' },
  { key: 'status', title: 'organizations.status', sortable: true },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  { key: 'actions', title: 'common.actions' },
]

/** Step-up action of the deletion request (plan M17 decision 2); the payload carries the organization. */
const deleteAction = 'organization-delete'
const stepUpTarget = 'organization'

// The deletion dialog of one row, and the problem of the last deletion or cancel attempt.
const deleting = ref<Organization | null>(null)
const deletionProblem = ref('')

function stepLabel(step: string): string {
  const key = 'organizations.deletion.steps.' + step
  return te(key) ? t(key) : step
}

async function runDeletion(input: OrganizationDeletionInput, stepUp: boolean): Promise<void> {
  deletionProblem.value = ''
  const failed = await requestOrganizationDeletion(input)
  if (failed === stepUpRequired && stepUp) {
    startStepUp(deleteAction, stepUpTarget, input)
    return
  }
  if (failed) deletionProblem.value = failed
  void list.value?.reload()
}

async function submitDeletion(answer: { reason: string; graceDays: number }): Promise<void> {
  const org = deleting.value
  if (!org) return
  deleting.value = null
  await runDeletion({ id: org.id, slug: org.slug, reason: answer.reason, graceDays: answer.graceDays }, true)
}

async function cancelDeletion(org: Organization): Promise<void> {
  const confirmed = await confirm({
    title: t('organizations.deletion.cancelTitle', { name: org.name }),
    message: t('organizations.deletion.cancelMessage', { name: org.name }),
    confirmLabel: t('organizations.deletion.cancelConfirm'),
    destructive: false,
  })
  if (!confirmed) return
  deletionProblem.value = (await cancelOrganizationDeletion(org.id)) ?? ''
  void list.value?.reload()
}

onMounted(async () => {
  const resumed = resumeStepUp<OrganizationDeletionInput>(deleteAction, stepUpTarget)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    deletionProblem.value = 'step_up_failed'
    return
  }
  await runDeletion(resumed.payload, false)
})

function openCreate(): void {
  slug.value = ''
  name.value = ''
  domains.value = ''
  touched.value = false
  problem.value = ''
  domainsNotSaved.value = false
  open.value = true
}

async function submit(): Promise<void> {
  touched.value = true
  if (hasErrors(errors.value) || validateDomains(domains.value)) return
  problem.value = ''
  domainsNotSaved.value = false
  provisioning.value = true
  const res = await createOrganization(slug.value, name.value).finally(() => {
    provisioning.value = false
  })
  if (typeof res === 'string') {
    problem.value = res
  } else if (parseDomains(domains.value).length > 0) {
    const failed = await updateOrganizationDomains(res.id, parseDomains(domains.value))
    if (failed) {
      problem.value = failed
      domainsNotSaved.value = true
    }
  }
  // A failed provisioning still stores the organization (status provisioning_failed).
  void list.value?.reload()
  if (!problem.value) open.value = false
}

function openDomains(org: Organization): void {
  editing.value = org
  editDomains.value = org.domains.join('\n')
  editTouched.value = false
  editProblem.value = ''
}

async function saveDomains(): Promise<void> {
  editTouched.value = true
  if (!editing.value || validateDomains(editDomains.value)) return
  editProblem.value = (await updateOrganizationDomains(editing.value.id, parseDomains(editDomains.value))) ?? ''
  if (editProblem.value) return
  editing.value = null
  void list.value?.reload()
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('organizations.title') }}</h1>
      <v-btn
        color="primary"
        data-testid="create-organization"
        @click="openCreate"
      >
        {{ t('organizations.create') }}
      </v-btn>
    </div>
    <p
      v-if="deletionProblem"
      class="form-error"
      role="alert"
      data-testid="organization-deletion-problem"
    >
      {{ problemText(deletionProblem) }}
    </p>
    <SetupChecklist />
    <UpgradeCard />
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listOrganizations"
      :filters="organizationFilters"
      searchable
      default-sort="slug"
      item-value="id"
      empty-icon="building-complex"
      empty-title="organizations.empty.title"
      empty-description="organizations.empty.description"
      data-testid="organization-list"
    >
      <template #empty-action>
        <v-btn
          v-if="true"
          color="primary"
          @click="openCreate"
        >
          {{ t('organizations.create') }}
        </v-btn>
      </template>
      <template #[`item.domains`]="{ item }: { item: Organization }">
        <span
          class="org-domains"
          :title="item.domains.join(', ')"
          :data-testid="'org-domains-text-' + item.slug"
        >{{ item.domains.join(', ') }}</span>
      </template>
      <template #[`item.status`]="{ item }: { item: Organization }">
        <StatusChip
          :status="organizationStatus(item.status).status"
          :label="t(organizationStatus(item.status).label)"
        />
        <StatusChip
          v-if="deletionPending(item) && item.deletion"
          status="warn"
          :label="t('organizations.deletion.pending', { date: formatDateTime(item.deletion.delete_after, locale) })"
          :data-testid="'org-deletion-pending-' + item.slug"
        />
        <StatusChip
          v-if="item.deletion?.audit_final_outcome === 'failed'"
          status="critical"
          :label="t('organizations.audit.finalFailedChip')"
          :data-testid="'org-audit-failed-' + item.slug"
        />
        <p
          v-if="item.deletion && item.status === 'deleting'"
          class="org-step"
          :data-testid="'org-deletion-step-' + item.slug"
        >
          <span v-if="item.deletion.step">{{ t('organizations.deletion.step', { step: stepLabel(item.deletion.step) }) }}</span>
          <span v-if="item.deletion.last_error_code">{{ t('organizations.deletion.lastError', { error: problemText(item.deletion.last_error_code) }) }}</span>
        </p>
      </template>
      <template #[`item.created_at`]="{ item }: { item: Organization }">
        <TimeCell :iso="item.created_at" />
      </template>
      <template #[`item.actions`]="{ item }: { item: Organization }">
        <v-btn
          size="small"
          variant="tonal"
          :data-testid="'org-domains-' + item.slug"
          @click="openDomains(item)"
        >
          {{ t('organizations.editDomains') }}
        </v-btn>
        <v-btn
          v-if="canRequestDeletion(item)"
          size="small"
          variant="tonal"
          color="error"
          :data-testid="'org-delete-' + item.slug"
          @click="deleting = item"
        >
          {{ t('organizations.delete.action') }}
        </v-btn>
        <v-btn
          v-if="item.status === 'deleted'"
          size="small"
          variant="tonal"
          :to="{ name: 'organization-audit', params: { id: item.id } }"
          :data-testid="'org-audit-' + item.slug"
        >
          {{ t('organizations.audit.open') }}
        </v-btn>
        <v-btn
          v-if="deletionPending(item)"
          size="small"
          variant="tonal"
          :data-testid="'org-cancel-deletion-' + item.slug"
          @click="cancelDeletion(item)"
        >
          {{ t('organizations.deletion.cancel') }}
        </v-btn>
      </template>
    </DataList>

    <OrganizationDeleteDialog
      v-if="deleting"
      :org="deleting"
      @confirm="submitDeletion"
      @cancel="deleting = null"
    />

    <v-dialog
      v-model="open"
      max-width="32rem"
      :aria-label="t('organizations.createTitle')"
    >
      <v-card :title="t('organizations.createTitle')">
        <v-card-text>
          <form
            class="form"
            novalidate
            @submit.prevent="run(submit)"
          >
            <v-text-field
              id="org-slug"
              v-model="slug"
              :label="t('organizations.slug')"
              autocomplete="off"
              :error-messages="slugError ? [slugError] : []"
              :aria-invalid="!!slugError"
            />
            <v-text-field
              id="org-name"
              v-model="name"
              :label="t('common.name')"
              autocomplete="off"
              :error-messages="nameError ? [nameError] : []"
              :aria-invalid="!!nameError"
            />
            <v-textarea
              id="org-domains"
              v-model="domains"
              :label="t('organizations.domains')"
              :hint="t('organizations.domainsHint')"
              persistent-hint
              rows="2"
              autocomplete="off"
              :error-messages="domainsError ? [domainsError] : []"
              :aria-invalid="!!domainsError"
            />
            <p
              v-if="provisioning"
              role="status"
              data-testid="org-provisioning"
            >
              {{ t('organizations.provisioning') }}
            </p>
            <div
              v-if="problem"
              class="form-error"
              role="alert"
            >
              <p>{{ problemText(problem) }}</p>
              <p v-if="domainsNotSaved">
                {{ t('organizations.createdWithoutDomains') }}
              </p>
            </div>
            <div class="form-actions">
              <v-btn
                type="button"
                variant="tonal"
                @click="open = false"
              >
                {{ t('common.cancel') }}
              </v-btn>
              <v-btn
                type="submit"
                :loading="pending"
                :disabled="pending"
                color="primary"
              >
                {{ t('common.create') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>

    <v-dialog
      :model-value="editing !== null"
      max-width="32rem"
      :aria-label="editing ? t('organizations.editDomainsTitle', { name: editing.name }) : ''"
      @update:model-value="(v: boolean) => { if (!v) editing = null }"
    >
      <v-card
        v-if="editing"
        :title="t('organizations.editDomainsTitle', { name: editing.name })"
      >
        <v-card-text>
          <form
            class="form"
            novalidate
            @submit.prevent="run(saveDomains)"
          >
            <v-textarea
              id="org-edit-domains"
              v-model="editDomains"
              :label="t('organizations.domains')"
              :hint="t('organizations.domainsHint')"
              persistent-hint
              rows="2"
              autocomplete="off"
              :error-messages="editError ? [editError] : []"
              :aria-invalid="!!editError"
            />
            <p
              v-if="editProblem"
              class="form-error"
              role="alert"
            >
              {{ problemText(editProblem) }}
            </p>
            <div class="form-actions">
              <v-btn
                type="button"
                variant="tonal"
                @click="editing = null"
              >
                {{ t('common.cancel') }}
              </v-btn>
              <v-btn
                type="submit"
                :loading="pending"
                :disabled="pending"
                color="primary"
                data-testid="save-domains"
              >
                {{ t('common.save') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>

<style scoped>
.org-step {
  margin: 0;
  font-size: 0.8125rem;
}

.org-domains {
  display: inline-block;
  max-width: 20rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}
</style>
