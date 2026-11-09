<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import PdIcon from '../components/PdIcon'
import SoftwareAssignmentForm from '../components/SoftwareAssignmentForm.vue'
import SoftwareCatalogEntryForm from '../components/SoftwareCatalogEntryForm.vue'
import SoftwareStateChip from '../components/SoftwareStateChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { SoftwareAssignment, SoftwareCatalogDevice, SoftwareCatalogEntry } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import { allGroups, groupFilter } from '../lib/devices'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import {
  allSoftwareSources, deleteCatalogEntry, deleteSoftwareAssignment, getCatalogEntry, iconFileProblem, iconUrl, listSoftwareAssignments,
  listSoftwareCatalogDevices, saveCatalogEntry, saveSoftwareAssignment, setCatalogIcon, softwareIntentFilter, softwareStateFilter,
  type AssignmentInput, type EntryInput,
} from '../lib/software'
import { useSessionStore } from '../stores/session'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const problemText = useProblemText()
const confirm = useConfirm()
const session = useSessionStore()
const { pending, run } = usePending()
const id = computed(() => String(route.params.id))
const entry = ref<SoftwareCatalogEntry | null>(null)
const problem = ref('')
const groups = ref<{ id: string; name: string }[]>([])
const sources = ref<{ id: string; slug: string; name: string }[]>([])
const iconVersion = ref(0)
const iconError = ref('')
const entryOpen = ref(false)
const entryProblem = ref('')
const assignmentTarget = ref<SoftwareAssignment | null>(null)
const assignmentOpen = ref(false)
const assignmentProblem = ref('')
const formKey = ref(0)
const assignments = ref<{ reload: () => Promise<void> } | null>(null)
const devices = ref<{ reload: () => Promise<void> } | null>(null)
const fetchAssignments = computed(() => listSoftwareAssignments(id.value))
const fetchDevices = computed(() => listSoftwareCatalogDevices(id.value))

const assignmentColumns = computed<ListColumn[]>(() => [
  { key: 'scope', title: 'managed.scope', role: 'primary' },
  { key: 'intent', title: 'software.assignments.intent', sortable: true, role: 'status' },
  { key: 'update_rule', title: 'software.assignments.updateRule', role: 'meta' },
  { key: 'version', title: 'software.assignments.version', role: 'meta', mono: true },
  { key: 'reason', title: 'software.assignments.reason', role: 'meta', hideBelow: 'md' },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true, role: 'meta' },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions', role: 'actions' as const }] : []),
])
const deviceColumns: ListColumn[] = [
  { key: 'hostname', title: 'devices.hostname', sortable: true, role: 'primary' },
  { key: 'name', title: 'devices.name.label', role: 'meta' },
  { key: 'state', title: 'software.state.label', sortable: true, role: 'status' },
  { key: 'intent', title: 'software.assignments.intent', role: 'meta' },
  { key: 'package', title: 'software.catalog.package', role: 'meta', mono: true },
  { key: 'version', title: 'software.assignments.version', role: 'meta', mono: true },
  { key: 'reported_at', title: 'software.reportedAt', sortable: true, role: 'meta' },
]
const deviceFilters = computed(() => [softwareStateFilter, groupFilter(groups.value)])

function groupName(groupID: string | null): string {
  if (!groupID) return t('managed.allDevices')
  return groups.value.find((g) => g.id === groupID)?.name ?? groupID
}

async function load(): Promise<void> {
  const res = await getCatalogEntry(id.value)
  if (typeof res === 'string') {
    problem.value = res
    entry.value = null
    return
  }
  problem.value = ''
  entry.value = res
}

onMounted(async () => {
  const [g, s] = await Promise.all([allGroups().catch(() => []), allSoftwareSources().catch(() => []), load()])
  groups.value = g
  sources.value = s
})

function openEntry(): void {
  entryProblem.value = ''
  formKey.value++
  entryOpen.value = true
}

async function submitEntry(input: EntryInput): Promise<void> {
  entryProblem.value = (await saveCatalogEntry(id.value, input)) ?? ''
  if (entryProblem.value) return
  entryOpen.value = false
  await load()
}

async function removeEntry(): Promise<void> {
  if (!entry.value) return
  const confirmed = await confirm({
    title: t('software.catalog.deleteTitle'),
    message: t('software.catalog.deleteConfirm'),
    confirmLabel: t('common.delete'),
    destructive: true,
    requireTypedText: entry.value.name,
  })
  if (!confirmed) return
  const code = await deleteCatalogEntry(id.value)
  if (code) {
    problem.value = code
    return
  }
  await router.push({ name: 'software-catalog' })
}

async function onIcon(e: Event): Promise<void> {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  iconError.value = ''
  if (!file) return
  const refused = iconFileProblem(file)
  if (refused) {
    iconError.value = t(refused)
    return
  }
  const code = await setCatalogIcon(id.value, file)
  if (code) {
    iconError.value = problemText(code)
    return
  }
  iconVersion.value = Date.now()
  await load()
}

function openAssignment(item: SoftwareAssignment | null): void {
  assignmentTarget.value = item
  assignmentProblem.value = ''
  formKey.value++
  assignmentOpen.value = true
}

async function submitAssignment(input: AssignmentInput): Promise<void> {
  assignmentProblem.value = (await saveSoftwareAssignment(assignmentTarget.value?.id ?? null, input)) ?? ''
  if (assignmentProblem.value) return
  assignmentOpen.value = false
  await Promise.all([assignments.value?.reload(), devices.value?.reload(), load()])
}

async function removeAssignment(item: SoftwareAssignment): Promise<void> {
  const confirmed = await confirm({
    title: t('software.assignments.deleteTitle'),
    message: t('software.assignments.deleteConfirm', { app: item.app_name, scope: groupName(item.device_group_id) }),
    confirmLabel: t('common.delete'),
    destructive: true,
  })
  if (!confirmed) return
  problem.value = (await deleteSoftwareAssignment(item.id)) ?? ''
  await Promise.all([assignments.value?.reload(), devices.value?.reload(), load()])
}
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'software-catalog' }">
        {{ t('software.catalog.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="entry">
      <div class="page-header">
        <div class="entry-title">
          <img
            v-if="entry.has_icon"
            :key="iconVersion"
            class="entry-icon"
            :src="iconUrl(entry.id, iconVersion)"
            alt=""
            data-testid="entry-icon"
          >
          <PdIcon
            v-else
            name="package"
            :size="32"
          />
          <h1>{{ entry.name }}</h1>
        </div>
        <div
          v-if="session.canWrite"
          class="row-actions"
        >
          <v-btn
            variant="tonal"
            data-testid="edit-entry"
            @click="openEntry"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            color="error"
            data-testid="delete-entry"
            :disabled="pending"
            @click="run(removeEntry)"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </div>
      <p class="summary">
        {{ entry.description }}
      </p>
      <dl class="entry-facts">
        <dt>{{ t('software.catalog.category') }}</dt>
        <dd>{{ entry.category || '–' }}</dd>
        <dt>{{ t('software.catalog.source') }}</dt>
        <dd>{{ entry.source_slug || t('software.catalog.distributionRepositories') }}</dd>
        <dt>{{ t('software.catalog.packages') }}</dt>
        <dd>
          <ul class="mono">
            <li
              v-for="p in entry.packages"
              :key="[p.distribution, p.release, p.architecture].join('/')"
            >
              {{ p.distribution }} {{ p.release }} {{ p.architecture }}: {{ p.package }}
            </li>
          </ul>
        </dd>
      </dl>
      <div
        v-if="session.canWrite"
        class="icon-upload"
      >
        <label for="entry-icon-file">{{ t('software.icon.upload') }}</label>
        <input
          id="entry-icon-file"
          type="file"
          accept="image/png"
          data-testid="icon-file"
          @change="onIcon"
        >
        <p class="summary">
          {{ t('software.icon.hint') }}
        </p>
        <p
          v-if="iconError"
          class="form-error"
          role="alert"
          data-testid="icon-error"
        >
          {{ iconError }}
        </p>
      </div>

      <div class="page-header">
        <h2>{{ t('software.assignments.title') }}</h2>
        <v-btn
          v-if="session.canWrite"
          color="primary"
          data-testid="create-assignment"
          @click="openAssignment(null)"
        >
          {{ t('software.assignments.create') }}
        </v-btn>
      </div>
      <DataList
        ref="assignments"
        query-prefix="a"
        :columns="assignmentColumns"
        :fetch="fetchAssignments"
        :filters="[softwareIntentFilter]"
        default-sort="-created_at"
        item-value="id"
        empty-icon="package"
        empty-title="software.assignments.empty.title"
        empty-description="software.assignments.empty.description"
        data-testid="assignment-list"
      >
        <template #[`item.scope`]="{ item }: { item: SoftwareAssignment }">
          {{ groupName(item.device_group_id) }}
        </template>
        <template #[`item.intent`]="{ item }: { item: SoftwareAssignment }">
          {{ t('software.intent.' + item.intent) }}
        </template>
        <template #[`item.update_rule`]="{ item }: { item: SoftwareAssignment }">
          {{ t('software.updateRule.' + item.update_rule) }}
        </template>
        <template #[`item.version`]="{ item }: { item: SoftwareAssignment }">
          {{ item.version ?? '–' }}
        </template>
        <template #[`item.reason`]="{ item }: { item: SoftwareAssignment }">
          {{ item.reason || '–' }}
        </template>
        <template #[`item.updated_at`]="{ item }: { item: SoftwareAssignment }">
          <TimeCell :iso="item.updated_at" />
        </template>
        <template #[`item.actions`]="{ item }: { item: SoftwareAssignment }">
          <div class="row-actions">
            <v-btn
              :aria-label="t('managed.editLabel', { name: groupName(item.device_group_id) })"
              variant="tonal"
              size="small"
              @click="openAssignment(item)"
            >
              {{ t('common.edit') }}
            </v-btn>
            <v-btn
              :aria-label="t('managed.deleteLabel', { name: groupName(item.device_group_id) })"
              color="error"
              size="small"
              :disabled="pending"
              @click="run(() => removeAssignment(item))"
            >
              {{ t('common.delete') }}
            </v-btn>
          </div>
        </template>
      </DataList>

      <h2>{{ t('software.catalog.devices') }}</h2>
      <DataList
        ref="devices"
        query-prefix="d"
        :columns="deviceColumns"
        :fetch="fetchDevices"
        :filters="deviceFilters"
        searchable
        default-sort="hostname"
        item-value="device_id"
        empty-icon="laptop"
        empty-title="software.catalog.devicesEmpty.title"
        empty-description="software.catalog.devicesEmpty.description"
        data-testid="catalog-device-list"
      >
        <template #[`item.hostname`]="{ item }: { item: SoftwareCatalogDevice }">
          <RouterLink :to="{ name: 'device-managed-software', params: { id: item.device_id } }">
            {{ item.hostname }}
          </RouterLink>
        </template>
        <template #[`item.name`]="{ item }: { item: SoftwareCatalogDevice }">
          {{ item.name || item.hostname }}
        </template>
        <template #[`item.state`]="{ item }: { item: SoftwareCatalogDevice }">
          <SoftwareStateChip
            :state="item.state"
            :reason="item.reason"
            :error="item.error"
          />
        </template>
        <template #[`item.intent`]="{ item }: { item: SoftwareCatalogDevice }">
          {{ t('software.intent.' + item.intent) }}
        </template>
        <template #[`item.package`]="{ item }: { item: SoftwareCatalogDevice }">
          {{ item.package || '–' }}
        </template>
        <template #[`item.version`]="{ item }: { item: SoftwareCatalogDevice }">
          {{ item.version || '–' }}
        </template>
        <template #[`item.reported_at`]="{ item }: { item: SoftwareCatalogDevice }">
          <TimeCell
            v-if="item.reported_at"
            :iso="item.reported_at"
            mode="relative"
          />
          <span
            v-else
            class="pd-muted"
          >–</span>
        </template>
      </DataList>

      <v-dialog
        v-model="entryOpen"
        max-width="56rem"
        :aria-label="t('software.catalog.editTitle')"
      >
        <v-card :title="t('software.catalog.editTitle')">
          <v-card-text>
            <SoftwareCatalogEntryForm
              :key="formKey"
              :sources="sources"
              :initial="entry"
              :problem="entryProblem"
              :pending="pending"
              @submit="run(() => submitEntry($event))"
              @cancel="entryOpen = false"
            />
          </v-card-text>
        </v-card>
      </v-dialog>
      <v-dialog
        v-model="assignmentOpen"
        max-width="40rem"
        :aria-label="assignmentTarget ? t('software.assignments.editTitle') : t('software.assignments.createTitle')"
      >
        <v-card :title="assignmentTarget ? t('software.assignments.editTitle') : t('software.assignments.createTitle')">
          <v-card-text>
            <SoftwareAssignmentForm
              :key="formKey"
              :entry-id="entry.id"
              :groups="groups"
              :initial="assignmentTarget"
              :problem="assignmentProblem"
              :pending="pending"
              @submit="run(() => submitAssignment($event))"
              @cancel="assignmentOpen = false"
            />
          </v-card-text>
        </v-card>
      </v-dialog>
    </template>
  </section>
</template>

<style scoped>
.entry-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.entry-icon {
  width: 32px;
  height: 32px;
  object-fit: contain;
}

.entry-facts {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.25rem 1rem;
}

.entry-facts dt {
  color: var(--pd-text-muted);
}

.entry-facts ul {
  margin: 0;
  padding-left: 1rem;
}

.icon-upload {
  margin-block: 1rem;
}
</style>
