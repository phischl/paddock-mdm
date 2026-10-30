<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { DeviceDiskConversion, DeviceUninstall, DiskState, RevocationRequest } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { conversionWarning } from '../lib/disk'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { listRevocations, requestRevocation, timeline, volumeResults, type RevokeAction, type VolumeResult } from '../lib/revocations'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'
import { cancelUninstall, requestUninstall, uninstallCancellable, uninstallPending, uninstallRunning, type UninstallAnswer } from '../lib/uninstall'
import { useSessionStore } from '../stores/session'
import PdIcon from './PdIcon'
import StatusChip from './StatusChip.vue'
import UninstallDialog from './UninstallDialog.vue'
import { revocationStatus } from '../lib/status'

/**
 * The danger zone of a device (plan M7c decision 24; plan M4c decision 18 flows unchanged): Lock, Destroy and
 * Retire, each with its own explanation, button and confirm dialog; the reason is collected in the dialog, no
 * shared field. Lock and Destroy go through a step-up, the typed hostname and the request; a Destroy waits for a
 * second administrator. Below the rows: the revocation timeline of the device's latest requests. Remove Paddock (plan
 * M8d decision 42) goes through the step-up and the uninstall dialog; a pending removal shows its state and, until
 * the device received the command, a cancel.
 */
const props = defineProps<{
  deviceId: string; hostname: string; revocable: boolean; presumedSelfLockedAt: string | null; retirable: boolean
  uninstallable?: boolean; uninstall?: DeviceUninstall | null; diskTpm?: boolean
  diskConversion?: DeviceDiskConversion | null; diskState?: DiskState | null
}>()
const emit = defineEmits<{ retire: []; changed: [] }>()

const { t, te, locale } = useI18n()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()

const problem = ref('')
const requested = ref<RevocationRequest | null>(null)
const requests = ref<RevocationRequest[]>([])
const uninstallOpen = ref(false)

const stepUpAction = (action: RevokeAction) => 'revocation-' + action

/** One volume of a confirmation (plan M4c.1 decision 2); a count of -1 means the device could not count the keyslots. */
function volumeText(v: VolumeResult): string {
  if (v.erased) return t('devices.revocation.volume.erased', { device: v.device, before: v.slots_before })
  if (v.slots_after < 0) return t('devices.revocation.volume.unknown', { device: v.device })
  return t('devices.revocation.volume.notErased', { device: v.device, after: v.slots_after })
}

async function load(): Promise<void> {
  try {
    const page = await listRevocations(props.deviceId)({ page: 1, page_size: 10, sort: '-requested_at' })
    requests.value = page.items
  } catch {
    // Operators and auditors may not list revocations; the timeline stays empty.
    requests.value = []
  }
}

/** The request starts with a step-up; the confirm dialog with the reason follows on return. */
function start(action: RevokeAction): void {
  problem.value = ''
  requested.value = null
  startStepUp(stepUpAction(action), props.deviceId, {})
}

async function resume(): Promise<void> {
  const stepped = resumeStepUp<Record<string, never>>('uninstall', props.deviceId)
  if (stepped) {
    await router.replace(withoutStepUpParam())
    if (stepped.failed) problem.value = 'step_up_failed'
    else uninstallOpen.value = true
    return
  }
  for (const action of ['lock', 'destroy'] as RevokeAction[]) {
    const resumed = resumeStepUp<Record<string, never>>(stepUpAction(action), props.deviceId)
    if (!resumed) continue
    await router.replace(withoutStepUpParam())
    if (resumed.failed) {
      problem.value = 'step_up_failed'
      return
    }
    await revoke(action)
    return
  }
}

async function revoke(action: RevokeAction): Promise<void> {
  const key = 'devices.revocation.' + action
  const warning = conversionWarning(props.diskConversion, props.diskState)
  const answer = await confirm({
    title: t(key + '.title'), message: t(key + '.confirm', { hostname: props.hostname }), confirmLabel: t(key + '.label'),
    destructive: true, requireTypedText: props.hostname,
    reason: { label: t('devices.revocation.reason'), hint: t('devices.revocation.reasonHint'), required: true, maxLength: 500 },
    warning: warning ? t('devices.danger.revoke.conversionWarning.' + warning) : undefined,
  })
  if (!answer) return
  const res = await requestRevocation(props.deviceId, action, props.hostname, answer.reason)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  requested.value = res
  await load()
  if (res.uninstall_cancelled) emit('changed')
}

/** The catalog text of a refusal reason, or the device's own word where the catalog has none (a newer agent's reason). */
function refusedReason(reason: string): string {
  const key = 'devices.uninstall.refusedReasons.' + reason
  return te(key) ? t(key) : reason
}

/** Remove Paddock starts with a step-up; the uninstall dialog follows on return. */
function startUninstall(): void {
  problem.value = ''
  startStepUp('uninstall', props.deviceId, {})
}

async function submitUninstall(answer: UninstallAnswer): Promise<void> {
  uninstallOpen.value = false
  const res = await requestUninstall(props.deviceId, props.hostname, answer)
  if (res) problem.value = res
  emit('changed')
}

async function cancel(): Promise<void> {
  problem.value = ''
  const answer = await confirm({
    title: t('devices.uninstall.cancel.title'), message: t('devices.uninstall.cancel.confirm', { hostname: props.hostname }),
    confirmLabel: t('devices.uninstall.cancel.label'),
  })
  if (!answer) return
  const res = await cancelUninstall(props.deviceId)
  if (res) problem.value = res
  emit('changed')
}

onMounted(async () => {
  if (!session.canDelete) return
  await load()
  await resume()
})
</script>

<template>
  <section
    v-if="session.canDelete"
    id="danger-zone"
    class="pd-danger"
    :aria-labelledby="'danger-zone-title'"
    data-testid="revocation"
  >
    <div class="pd-danger-header">
      <PdIcon name="triangle-alert" />
      <h2
        id="danger-zone-title"
        tabindex="-1"
        class="pd-danger-title"
      >
        {{ t('devices.danger.title') }}
      </h2>
      <span class="pd-danger-caption pd-type-caption">{{ t('devices.danger.caption') }}</span>
    </div>
    <v-alert
      v-if="presumedSelfLockedAt"
      type="warning"
      variant="tonal"
      class="conflict pd-danger-alert"
      data-testid="presumed-self-locked"
    >
      {{ t('devices.revocation.presumedSelfLocked', { at: formatDateTime(presumedSelfLockedAt, locale) }) }}
    </v-alert>
    <v-alert
      v-if="!session.me?.revocation_enabled"
      type="info"
      variant="tonal"
      class="conflict pd-danger-alert"
      data-testid="revocation-disabled"
    >
      {{ t('revocations.disabled') }}
    </v-alert>
    <template v-else-if="revocable">
      <div
        class="pd-danger-row"
        data-testid="danger-lock"
      >
        <div class="pd-danger-text">
          <div class="pd-danger-row-title">
            {{ t('devices.danger.lock.title') }}
          </div>
          <p>{{ t('devices.danger.lock.explanation') }}</p>
        </div>
        <v-btn
          color="error"
          variant="flat"
          data-testid="revocation-lock"
          @click="start('lock')"
        >
          {{ t('devices.danger.lock.label') }}
        </v-btn>
      </div>
      <div
        class="pd-danger-row"
        data-testid="danger-destroy"
      >
        <div class="pd-danger-text">
          <div class="pd-danger-row-title">
            {{ t('devices.danger.destroy.title') }}
          </div>
          <p>{{ t('devices.danger.destroy.explanation') }}</p>
        </div>
        <v-btn
          color="error"
          variant="outlined"
          data-testid="revocation-destroy"
          @click="start('destroy')"
        >
          {{ t('devices.danger.destroy.label') }}
        </v-btn>
      </div>
    </template>
    <div
      v-if="uninstallPending(uninstall)"
      class="pd-danger-row"
      data-testid="danger-uninstall-pending"
    >
      <div class="pd-danger-text">
        <div class="pd-danger-row-title">
          {{ t('devices.danger.uninstall.title') }}
        </div>
        <p role="status">
          {{ t('devices.uninstall.pending', {
            mode: t('devices.uninstall.modes.' + uninstall!.mode), status: t('commands.statuses.' + uninstall!.command_status),
          }) }}
          <template v-if="uninstallRunning(uninstall)">
            {{ t('devices.uninstall.running') }}
          </template>
        </p>
        <p
          v-if="uninstall!.refused_reason"
          data-testid="uninstall-refused"
        >
          {{ t('devices.uninstall.refused', { reason: refusedReason(uninstall!.refused_reason) }) }}
        </p>
        <p
          v-else-if="!uninstallRunning(uninstall)"
          data-testid="uninstall-stopped"
        >
          {{ t('devices.uninstall.stopped') }}
        </p>
      </div>
      <v-btn
        v-if="uninstallCancellable(uninstall)"
        variant="outlined"
        data-testid="uninstall-cancel-request"
        @click="cancel"
      >
        {{ t('devices.uninstall.cancel.label') }}
      </v-btn>
    </div>
    <div
      v-else-if="uninstallable"
      class="pd-danger-row"
      data-testid="danger-uninstall"
    >
      <div class="pd-danger-text">
        <div class="pd-danger-row-title">
          {{ t('devices.danger.uninstall.title') }}
        </div>
        <p>{{ t('devices.danger.uninstall.explanation') }}</p>
      </div>
      <v-btn
        color="error"
        variant="outlined"
        data-testid="device-uninstall"
        @click="startUninstall"
      >
        {{ t('devices.danger.uninstall.label') }}
      </v-btn>
    </div>
    <div
      v-if="retirable"
      class="pd-danger-row"
      data-testid="danger-retire"
    >
      <div class="pd-danger-text">
        <div class="pd-danger-row-title">
          {{ t('devices.danger.retire.title') }}
        </div>
        <p>{{ t('devices.danger.retire.explanation') }}</p>
      </div>
      <v-btn
        color="error"
        variant="outlined"
        data-testid="device-retire"
        @click="emit('retire')"
      >
        {{ t('devices.danger.retire.label') }}
      </v-btn>
    </div>
    <UninstallDialog
      :model-value="uninstallOpen"
      :hostname="hostname"
      :disk-tpm="!!diskTpm"
      :conversion-active="!!diskConversion?.active"
      @confirm="submitUninstall"
      @cancel="uninstallOpen = false"
    />
    <p
      v-if="problem"
      class="form-error pd-danger-note"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <p
      v-if="requested"
      class="pd-danger-note"
      role="status"
      data-testid="revocation-requested"
    >
      {{ t('devices.revocation.requested.' + (requested.action === 'destroy' ? 'destroy' : 'lock')) }}
    </p>
    <v-alert
      v-if="requested?.uninstall_cancelled"
      :type="requested.uninstall_cancelled === 'after_delivery' ? 'warning' : 'info'"
      variant="tonal"
      class="conflict pd-danger-alert"
      data-testid="revocation-uninstall-cancelled"
    >
      {{ t('devices.revocation.uninstallCancelled.' + requested.uninstall_cancelled) }}
    </v-alert>
    <v-table
      v-if="requests.length > 0"
      class="table pd-danger-timeline"
      data-testid="revocation-timeline"
    >
      <caption>{{ t('devices.revocation.timeline') }}</caption>
      <thead>
        <tr>
          <th scope="col">
            {{ t('revocations.action') }}
          </th>
          <th scope="col">
            {{ t('revocations.status') }}
          </th>
          <th scope="col">
            {{ t('devices.revocation.steps') }}
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="r in requests"
          :key="r.id"
        >
          <td>{{ t('revocations.actions.' + r.action) }}</td>
          <td>
            <StatusChip
              :status="revocationStatus(r.status).status"
              :label="t(revocationStatus(r.status).label)"
            />
            <span v-if="r.rejection"> ({{ r.rejection }})</span>
          </td>
          <td>
            <ol class="timeline">
              <li
                v-for="s in timeline(r)"
                :key="s.step"
              >
                {{ t('devices.revocation.timelineSteps.' + s.step, { at: formatDateTime(s.at, locale) }) }}
              </li>
            </ol>
            <p
              v-if="volumeResults(r).incomplete"
              class="incomplete"
              data-testid="revocation-incomplete"
            >
              {{ t('devices.revocation.incomplete') }}
            </p>
            <ul
              v-if="volumeResults(r).volumes.length > 0 || volumeResults(r).unresolved.length > 0 || volumeResults(r).skipped.length > 0 || volumeResults(r).shared.length > 0"
              class="volumes"
              :aria-label="t('devices.revocation.volumes')"
              data-testid="revocation-volumes"
            >
              <li
                v-for="(v, i) in volumeResults(r).volumes"
                :key="'v' + i + ':' + v.device"
              >
                {{ volumeText(v) }}
                <div
                  v-if="typeof v.other_slots_after === 'number' && v.other_slots_after > 0"
                  data-testid="revocation-other-slots"
                >
                  {{ t('devices.danger.revoke.otherSlotsLeft', { count: v.other_slots_after }) }}
                </div>
              </li>
              <li
                v-for="(source, i) in volumeResults(r).unresolved"
                :key="'u' + i + ':' + source"
              >
                {{ t('devices.revocation.volume.unresolved', { source }) }}
              </li>
              <li
                v-for="(v, i) in volumeResults(r).skipped"
                :key="'s' + i + ':' + v.device"
                data-testid="revocation-skipped"
              >
                {{ t('devices.revocation.volume.skipped', { device: v.device }) }}
              </li>
              <li
                v-for="(device, i) in volumeResults(r).shared"
                :key="'h' + i + ':' + device"
              >
                {{ t('devices.revocation.volume.shared', { device }) }}
              </li>
            </ul>
          </td>
        </tr>
      </tbody>
    </v-table>
  </section>
</template>
