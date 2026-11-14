<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import InstallNowDialog from '../components/InstallNowDialog.vue'
import MaintenanceWindowForm from '../components/MaintenanceWindowForm.vue'
import { api, problemCode, type Device, type DeviceGroup, type MaintenanceWindow, type MaintenanceWindowInput } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import { effectiveStaleness } from '../lib/deviceGroups'
import { deleteMaintenanceWindow, getMaintenanceWindow, minutesToClock, setMaintenanceWindow } from '../lib/maintenanceWindows'
import { listGroupDevices, stateFilter } from '../lib/devices'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { getUpdateSettings, installNowGroup } from '../lib/updates'
import { useSessionStore } from '../stores/session'
import { deviceStatus } from '../lib/status'

const { t } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const session = useSessionStore()
const id = computed(() => String(route.params.id))
const installOpen = ref(false)
const notice = ref('')
const confirm = useConfirm()
const { pending, run } = usePending()
const maintenanceWindow = ref<MaintenanceWindow | null>(null)
const windowProblem = ref('')
// Without a loaded window the page cannot tell "none" from "unknown"; offering Set window would replace an unseen one.
const windowLoadFailed = ref(false)
const windowOpen = ref(false)
const windowFormProblem = ref('')
const windowFormKey = ref(0)

async function install(packages: string[]): Promise<{ problem: string; detail?: string } | null> {
  const res = await installNowGroup(id.value, packages)
  if (typeof res !== 'number') return res
  notice.value = t('updates.installNow.requestedGroup', { count: res })
  return null
}
const group = ref<DeviceGroup | null>(null)
const problem = ref('')
const orgSettings = ref<{ staleness_warning_h: number; staleness_critical_h: number } | null>(null)
onMounted(async () => {
  const [{ data, error }, settings] = await Promise.all([
    api.GET('/api/v1/device-groups/{id}', { params: { path: { id: id.value } } }),
    getUpdateSettings().catch(() => 'unavailable'),
  ])
  group.value = data ?? null
  problem.value = data ? '' : problemCode(error)
  orgSettings.value = typeof settings === 'string' ? null : settings
  if (data) await loadWindow()
})

async function loadWindow(): Promise<void> {
  const res = await getMaintenanceWindow(id.value)
  windowProblem.value = typeof res === 'string' ? res : ''
  windowLoadFailed.value = typeof res === 'string'
  maintenanceWindow.value = typeof res === 'string' ? null : res
}

const windowSummary = computed(() => {
  const w = maintenanceWindow.value
  if (!w) return ''
  return t('maintenanceWindow.summary', {
    days: w.days.map((d) => t('maintenanceWindow.weekdaysShort.' + d)).join(', '),
    start: minutesToClock(w.start_minute),
    duration: t('maintenanceWindow.durationValue', { hours: Math.floor(w.duration_minutes / 60), minutes: w.duration_minutes % 60 }).trim(),
    timezone: w.timezone,
  })
})

function openWindow(): void {
  windowFormProblem.value = ''
  windowFormKey.value++
  windowOpen.value = true
}

async function submitWindow(input: MaintenanceWindowInput): Promise<void> {
  const res = await setMaintenanceWindow(id.value, input)
  if (typeof res === 'string') {
    windowFormProblem.value = res
    return
  }
  maintenanceWindow.value = res
  windowProblem.value = ''
  windowOpen.value = false
}

async function removeWindow(): Promise<void> {
  if (!group.value) return
  const confirmed = await confirm({
    title: t('maintenanceWindow.removeTitle'),
    message: t('maintenanceWindow.removeConfirm', { name: group.value.name }),
    confirmLabel: t('maintenanceWindow.remove'),
    destructive: true,
  })
  if (!confirmed) return
  const code = await deleteMaintenanceWindow(id.value)
  if (code) {
    windowProblem.value = code
    return
  }
  await loadWindow()
}
const staleness = computed(() => (group.value ? effectiveStaleness(group.value, orgSettings.value) : null))

const fetchMembers = computed(() => listGroupDevices(id.value))
const columns: ListColumn[] = [
  { key: 'hostname', title: 'devices.hostname', sortable: true },
  { key: 'state', title: 'devices.state', sortable: true },
  { key: 'last_contact_at', title: 'devices.lastContact', sortable: true },
  { key: 'enrolled_at', title: 'devices.enrolledAt', sortable: true },
]
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'device-groups' }">
        {{ t('deviceGroups.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="group">
      <div class="page-header">
        <h1>{{ group.name }}</h1>
        <v-btn
          v-if="session.canWrite"
          color="primary"
          data-testid="group-install-now"
          @click="installOpen = true"
        >
          {{ t('updates.installNow.label') }}
        </v-btn>
      </div>
      <p
        v-if="notice"
        role="status"
      >
        {{ notice }}
      </p>
      <p class="summary">
        {{ group.description }}
      </p>
      <p
        v-if="staleness"
        data-testid="group-effective-staleness"
      >
        {{ t('deviceGroups.staleness.effective', {
          warning: staleness.warning, critical: staleness.critical,
          source: t('deviceGroups.staleness.sources.' + staleness.source),
        }) }}
      </p>
      <div class="page-header">
        <h2>{{ t('maintenanceWindow.title') }}</h2>
        <div
          v-if="session.canWrite && !windowLoadFailed"
          class="row-actions"
        >
          <v-btn
            variant="tonal"
            data-testid="edit-window"
            @click="openWindow"
          >
            {{ maintenanceWindow ? t('maintenanceWindow.edit') : t('maintenanceWindow.set') }}
          </v-btn>
          <v-btn
            v-if="maintenanceWindow"
            color="error"
            :disabled="pending"
            data-testid="remove-window"
            @click="run(removeWindow)"
          >
            {{ t('maintenanceWindow.remove') }}
          </v-btn>
        </div>
      </div>
      <p
        v-if="windowProblem"
        class="form-error"
        role="alert"
      >
        {{ problemText(windowProblem) }}
      </p>
      <p
        v-if="!windowLoadFailed"
        data-testid="window-summary"
      >
        {{ maintenanceWindow ? windowSummary : t('maintenanceWindow.none') }}
      </p>
      <p class="summary">
        {{ t('maintenanceWindow.explain') }}
      </p>
      <h2>{{ t('deviceGroups.members') }}</h2>
      <DataList
        :columns="columns"
        :fetch="fetchMembers"
        :filters="[stateFilter]"
        searchable
        default-sort="hostname"
        item-value="id"
        data-testid="group-device-list"
      >
        <template #[`item.hostname`]="{ item }: { item: Device }">
          <RouterLink :to="{ name: 'device', params: { id: item.id } }">
            {{ item.hostname }}
          </RouterLink>
        </template>
        <template #[`item.state`]="{ item }: { item: Device }">
          <StatusChip
            :status="deviceStatus(item).status"
            :label="t(deviceStatus(item).label)"
          />
        </template>
        <template #[`item.last_contact_at`]="{ item }: { item: Device }">
          <TimeCell
            v-if="item.last_contact_at"
            :iso="item.last_contact_at"
            mode="relative"
          />
          <span
            v-else
            class="pd-muted"
          >{{ t('devices.never') }}</span>
        </template>
        <template #[`item.enrolled_at`]="{ item }: { item: Device }">
          <TimeCell :iso="item.enrolled_at" />
        </template>
      </DataList>
      <v-dialog
        v-model="windowOpen"
        max-width="40rem"
        :aria-label="t('maintenanceWindow.formTitle')"
      >
        <v-card :title="t('maintenanceWindow.formTitle')">
          <v-card-text>
            <MaintenanceWindowForm
              :key="windowFormKey"
              :initial="maintenanceWindow"
              :problem="windowFormProblem"
              :pending="pending"
              @submit="run(() => submitWindow($event))"
              @cancel="windowOpen = false"
            />
          </v-card-text>
        </v-card>
      </v-dialog>
      <InstallNowDialog
        v-model="installOpen"
        :title="t('updates.installNow.titleGroup', { name: group.name })"
        :install="install"
      />
    </template>
  </section>
</template>
