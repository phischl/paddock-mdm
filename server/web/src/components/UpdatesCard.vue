<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceReport, DeviceUpdates } from '../api/client'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { getDeviceUpdates } from '../lib/updates'

/**
 * The updates of a device (plan M5b decision 12): the last security and regular runs, a pending reboot, the holds
 * that apply to it with conflicting versions. Install now is in the device's header band (plan M7c decision 29);
 * refresh changes when a command was issued there.
 */
const props = defineProps<{ deviceId: string; refresh: number }>()

const { t, locale } = useI18n()
const problemText = useProblemText()
const state = ref<DeviceUpdates | null>(null)
const problem = ref('')

async function load(): Promise<void> {
  const s = await getDeviceUpdates(props.deviceId)
  if (typeof s === 'string') problem.value = s
  else state.value = s
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
watch(() => props.refresh, load)
</script>

<template>
  <section
    class="pd-panel device-updates"
    data-testid="device-updates"
    aria-labelledby="device-updates-title"
  >
    <header class="pd-panel-header">
      <h2
        id="device-updates-title"
        class="pd-type-section"
      >
        {{ t('updates.device.title') }}
      </h2>
    </header>
    <div class="pd-panel-body">
      <p
        v-if="problem"
        class="form-error"
        role="alert"
      >
        {{ problemText(problem) }}
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
        <dl class="pd-facts">
          <div>
            <dt>
              {{ t('updates.device.lastSecurity') }}
            </dt>
            <dd data-testid="last-security-run">
              {{ runText(state.last_security_run) }}
            </dd>
          </div>
          <div>
            <dt>
              {{ t('updates.device.lastRegular') }}
            </dt>
            <dd data-testid="last-regular-run">
              {{ runText(state.last_regular_run) }}
            </dd>
          </div>
          <div v-if="heldBack(state.last_regular_run)">
            <dt>
              {{ t('updates.device.heldBack') }}
            </dt>
            <dd>{{ heldBack(state.last_regular_run) }}</dd>
          </div>
          <div>
            <dt>
              {{ t('updates.device.holds') }}
            </dt>
            <dd data-testid="device-holds">
              {{ state.holds.length === 0 ? t('updates.device.noHolds') : state.holds.map((h) => h.version ? h.package + ' = ' + h.version : h.package).join(', ') }}
            </dd>
          </div>
        </dl>
      </template>
    </div>
  </section>
</template>
