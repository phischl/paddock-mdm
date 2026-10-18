<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useConfirm } from '../composables/useConfirm'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import { lockedByRevocation } from '../lib/deviceHealth'
import { agentUpdateProblemKey, requestAgentUpdate } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import { rotateLocalAdmin } from '../lib/localAdmin'
import { useProblemText } from '../lib/problems'
import { deviceStatus, encryptionStatus } from '../lib/status'
import { installNow } from '../lib/updates'
import { useSessionStore } from '../stores/session'
import InstallNowDialog from './InstallNowDialog.vue'
import StatusChip from './StatusChip.vue'
import TimeCell from './TimeCell.vue'

/**
 * The header band of a device (plan M7c decision 29): breadcrumb, hostname, status chips, the meta line and the
 * primary actions — approve, reject and release for pending or quarantined devices, Install updates and Rotate
 * admin password for active ones. Retire, Lock and Destroy live in the danger zone, never here.
 */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceHeader outside the device frame')
const { device, actions, diskState, revocations } = page

const { t, locale } = useI18n()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const installOpen = ref(false)
const notice = ref('')
const problem = ref('')

const d = computed(() => device.value!)
const state = computed(() => deviceStatus(d.value))
const encryption = computed(() => encryptionStatus(diskState.value))
const locked = computed(() => session.canDelete && lockedByRevocation(revocations.value))
const active = computed(() => d.value.state === 'active')
const lifecycle = computed(() => actions.value.filter((a) => a !== 'retire'))

async function install(packages: string[]): Promise<{ problem: string; detail?: string } | null> {
  const res = await installNow(d.value.id, packages)
  return 'problem' in res ? res : null
}

async function installed(): Promise<void> {
  problem.value = ''
  notice.value = t('updates.installNow.requested')
  await page!.changed()
}

/** Update agent now (plan M8d decision 29): a non-destructive confirmation, then the request. */
async function updateAgent(): Promise<void> {
  problem.value = ''
  notice.value = ''
  const confirmed = await confirm({
    title: t('devices.updateAgent.title'),
    message: t('devices.updateAgent.confirm', {
      version: d.value.agent_update_requested_version ?? t('devices.updateAgent.offered'), hostname: d.value.hostname,
    }),
    confirmLabel: t('devices.updateAgent.label'),
  })
  if (!confirmed) return
  const res = await requestAgentUpdate(d.value.id)
  if (res) {
    const key = agentUpdateProblemKey(res)
    if (key) notice.value = t(key)
    else problem.value = res.problem
  }
  await page!.changed()
}

async function rotate(): Promise<void> {
  problem.value = ''
  notice.value = ''
  const confirmed = await confirm({
    title: t('devices.localAdmin.rotate.title'), message: t('devices.localAdmin.rotate.confirm', { hostname: d.value.hostname }),
    confirmLabel: t('devices.localAdmin.rotate.label'),
  })
  if (!confirmed) return
  problem.value = (await rotateLocalAdmin(d.value.id)) ?? ''
  if (!problem.value) notice.value = t('devices.localAdmin.rotate.requested')
  await page!.changed()
}
</script>

<template>
  <header
    class="pd-device-header"
    data-testid="device-header"
  >
    <nav
      class="pd-breadcrumb pd-type-caption"
      :aria-label="t('devices.breadcrumb')"
    >
      <RouterLink :to="{ name: 'devices' }">
        {{ t('nav.devices') }}
      </RouterLink>
      <span aria-hidden="true">/</span>
      <span
        class="mono"
        aria-current="page"
      >{{ d.hostname }}</span>
    </nav>
    <div class="pd-device-title">
      <div class="pd-device-name">
        <h1
          class="pd-type-title-mono pd-truncate"
          :title="d.hostname"
        >
          {{ d.hostname }}
        </h1>
        <span class="pd-chips">
          <StatusChip
            :status="state.status"
            :label="t(state.label)"
            :title="d.state === 'active' ? t('devices.contactHint') : undefined"
          >
            <span data-testid="device-state">{{ t(state.label) }}</span>
          </StatusChip>
          <StatusChip
            :status="encryption.status"
            :label="t(encryption.label)"
          />
          <StatusChip
            v-if="d.logins_suspended"
            status="info"
            :label="t('status.loginsSuspended')"
          />
          <StatusChip
            v-if="locked"
            status="info"
            :label="t('status.locked')"
          />
        </span>
      </div>
      <div class="row-actions pd-device-actions">
        <v-btn
          v-for="action in lifecycle"
          :key="action"
          :color="action === 'reject' ? 'error' : 'primary'"
          :data-testid="'device-' + action"
          @click="page!.run(action)"
        >
          {{ t('devices.actions.' + action + '.label') }}
        </v-btn>
        <v-btn
          v-if="session.canWrite && active"
          data-testid="install-now"
          @click="installOpen = true"
        >
          {{ t('devices.header.install') }}
        </v-btn>
        <v-btn
          v-if="session.canWrite && active"
          data-testid="update-agent"
          @click="updateAgent"
        >
          {{ t('devices.updateAgent.label') }}
        </v-btn>
        <v-btn
          v-if="session.canWrite && active"
          data-testid="local-admin-rotate"
          @click="rotate"
        >
          {{ t('devices.header.rotate') }}
        </v-btn>
      </div>
    </div>
    <p class="pd-type-caption pd-secondary pd-device-meta">
      <span>{{ t('devices.header.os') }} <span :class="d.os_release.VERSION_ID ? 'mono' : 'pd-muted'">{{ d.os_release.VERSION_ID ?? t('devices.header.unknown') }}</span></span>
      <span aria-hidden="true">·</span>
      <span>{{ t('devices.header.agent') }} <span :class="d.agent_version ? 'mono' : 'pd-muted'">{{ d.agent_version ?? t('devices.header.unknown') }}</span></span>
      <span aria-hidden="true">·</span>
      <span>
        {{ t('devices.header.lastContact') }}
        <template v-if="d.last_contact_at">
          <TimeCell :iso="d.last_contact_at" />
          (<TimeCell
            :iso="d.last_contact_at"
            mode="relative"
          />)
        </template>
        <span
          v-else
          class="pd-muted"
          :title="t('devices.noReportYet')"
        >{{ t('time.never') }}</span>
      </span>
    </p>
    <p
      v-if="d.agent_update_requested_version && d.agent_update_requested_at"
      class="pd-type-caption"
      data-testid="update-agent-requested"
    >
      {{ t('devices.updateAgent.requested', {
        version: d.agent_update_requested_version, at: formatDateTime(d.agent_update_requested_at, locale),
      }) }}
    </p>
    <p
      v-if="notice"
      role="status"
      class="pd-device-notice"
    >
      {{ notice }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <InstallNowDialog
      v-model="installOpen"
      :title="t('updates.installNow.titleDevice', { hostname: d.hostname })"
      :install="install"
      @done="installed"
    />
  </header>
</template>
