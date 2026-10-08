<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceReport, DeviceUpdates } from '../api/client'
import InstallNowDialog from './InstallNowDialog.vue'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { getDeviceUpdates, installNow } from '../lib/updates'
import { useSessionStore } from '../stores/session'

/**
 * The updates of a device (plan M5b decision 12): the last security and regular runs, a pending reboot, the holds
 * that apply to it with conflicting versions, and Install now.
 */
const props = defineProps<{ deviceId: string; hostname: string; active: boolean }>()
const emit = defineEmits<{ changed: [] }>()

const { t, locale } = useI18n()
const problemText = useProblemText()
const session = useSessionStore()
const state = ref<DeviceUpdates | null>(null)
const problem = ref('')
const notice = ref('')
const dialog = ref(false)

async function load(): Promise<void> {
  const s = await getDeviceUpdates(props.deviceId)
  if (typeof s === 'string') problem.value = s
  else state.value = s
}

async function install(packages: string[]): Promise<{ problem: string; detail?: string } | null> {
  const res = await installNow(props.deviceId, packages)
  return 'problem' in res ? res : null
}

function done(): void {
  notice.value = t('updates.installNow.requested')
  emit('changed')
}

/** The summary of an updates.run report. */
function runText(r: DeviceReport | null): string {
  if (!r) return t('updates.device.noRun')
  const p = r.params
  const at = formatDateTime(String(p.finished_at ?? r.occurred_at), locale.value)
  return t('updates.device.run', { result: String(p.result ?? ''), upgraded: Number(p.upgraded ?? 0), at })
}

function heldBack(r: DeviceReport | null): string {
  const list = r?.params.held_back
  return Array.isArray(list) && list.length > 0 ? list.join(', ') : ''
}

onMounted(load)
</script>

<template>
  <section
    class="device-updates"
    data-testid="device-updates"
  >
    <div class="page-header">
      <h2>{{ t('updates.device.title') }}</h2>
      <v-btn
        v-if="session.canWrite && active"
        color="primary"
        data-testid="install-now"
        @click="dialog = true"
      >
        {{ t('updates.installNow.label') }}
      </v-btn>
    </div>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <p
      v-if="notice"
      role="status"
    >
      {{ notice }}
    </p>
    <template v-if="state">
      <v-alert
        v-if="state.reboot_required"
        type="info"
        variant="tonal"
        class="conflict"
        data-testid="reboot-required"
      >
        {{ t('updates.device.rebootRequired') }}
      </v-alert>
      <v-alert
        v-for="c in state.conflicts"
        :key="c.package"
        type="warning"
        variant="tonal"
        class="conflict"
        data-testid="hold-conflict"
      >
        {{ t('updates.device.conflict', {
          package: c.package,
          versions: c.versions.map((v) => v ?? t('updates.holds.installedVersion')).join(', '),
          chosen: c.chosen ?? t('updates.holds.installedVersion'),
        }) }}
      </v-alert>
      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('updates.device.lastSecurity') }}
            </th>
            <td data-testid="last-security-run">
              {{ runText(state.last_security_run) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('updates.device.lastRegular') }}
            </th>
            <td data-testid="last-regular-run">
              {{ runText(state.last_regular_run) }}
            </td>
          </tr>
          <tr v-if="heldBack(state.last_regular_run)">
            <th scope="row">
              {{ t('updates.device.heldBack') }}
            </th>
            <td>{{ heldBack(state.last_regular_run) }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('updates.device.holds') }}
            </th>
            <td data-testid="device-holds">
              {{ state.holds.length === 0 ? t('updates.device.noHolds') : state.holds.map((h) => h.version ? h.package + ' = ' + h.version : h.package).join(', ') }}
            </td>
          </tr>
        </tbody>
      </v-table>
    </template>
    <InstallNowDialog
      v-model="dialog"
      :title="t('updates.installNow.titleDevice', { hostname })"
      :install="install"
      @done="done"
    />
  </section>
</template>
