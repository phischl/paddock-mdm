<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { DiskEncryption, DiskRecoveryKey, DiskVolume } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import {
  abortIssuedAt, abortOpen, cancelEncrypt, conversionCancellable, conversionEstimate, conversionOpen, conversionPercent,
  conversionRunbook, diskStateLabel, downloadHeader, formatDuration, getDisk, headerDevice, latestStored, requestEncrypt,
  revealRecoveryKey, saveFile, unlockModeRunbook, volumeHeaders,
} from '../lib/disk'
import { formatDateTime, formatGB, formatMiB } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'
import EncryptDiskDialog from './EncryptDiskDialog.vue'

/**
 * The disk encryption of a device (plan M4b decision 14): state, keyslots, every LUKS volume (PDK-009), escrowed
 * generations, the last keyslot change, and for organization administrators the recovery key and the header of each
 * volume — each after a step-up and the typed hostname. The recovery key lives only in this component while its
 * dialog is open and is hidden after 60 s. An unencrypted device shows whether it can be encrypted in place and, for
 * organization administrators of an active device, starts it; the card follows the conversion until the disk is
 * compliant (plan M8e decisions 24 and 25).
 */
const props = defineProps<{ deviceId: string; hostname: string; active?: boolean; diskTotalBytes?: number | null }>()

/** Seconds until a revealed recovery key is hidden. */
const hideAfter = 60

type Action = 'disk-recovery-key' | 'disk-header' | 'disk-convert' | 'disk-convert-cancel'

const { t, te, locale } = useI18n()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()

const disk = ref<DiskEncryption | null>(null)
const problem = ref('')
const revealed = ref<DiskRecoveryKey | null>(null)
const remaining = ref(hideAfter)
const copied = ref(false)
let timer: ReturnType<typeof setInterval> | undefined
const encryptOpen = ref(false)
/** The outcome of the administrator's own request or cancel, shown until the next one. */
const notice = ref<'requested' | 'cancelled' | ''>('')
const abortAt = ref<string | null>(null)

const health = computed(() => disk.value?.conversion ?? null)
const conversion = computed(() => disk.value?.disk_conversion ?? null)
const canEncrypt = computed(() => session.canDelete && !!props.active && disk.value?.state === 'not_encrypted' &&
  !!health.value?.eligible && !conversionOpen(conversion.value))
const canCancel = computed(() => session.canDelete && conversionCancellable(conversion.value))
/** The conversion's progress panel, shown until a completed conversion's disk is compliant. */
const showConversion = computed(() => !!conversion.value && !(conversion.value.phase === 'completed' && disk.value?.state === 'compliant'))
/** A cancellation after delivery is on its way and the device has not answered it (plan M8e decision 8). */
const cancelSent = computed(() => {
  const c = conversion.value
  return !!c && abortOpen(c) && (c.phase === 'requested' || c.phase === 'prepared')
})
const keyOnBoot = computed(() => {
  const phase = conversion.value?.phase ?? health.value?.phase
  return !!health.value?.key_on_boot && (phase === 'encrypting' || phase === 'completed')
})

const recovery = computed(() => (disk.value ? latestStored(disk.value.recovery_keys) : null))
const header = computed(() => (disk.value ? latestStored(disk.value.headers) : null))
const headers = computed(() => disk.value?.headers.slice(0, 5) ?? [])
const volumes = computed(() => disk.value?.volumes ?? [])
/** The volumes with a stored header to download; empty for a device that reports no volumes (before PDK-009). */
const downloadable = computed(() => volumes.value.filter((v) => v.uuid && latestStored(volumeHeaders(disk.value?.headers ?? [], v))))

function volumeText(v: DiskVolume): string {
  if (!v.uuid) return t('devices.disk.volumeUnknown', { device: v.device })
  if (v.shared_uuid) return t('devices.disk.volumeShared', { device: v.device })
  if (v.refused) return t('devices.disk.volumeRefused', { device: v.device })
  return t('devices.disk.volumeFacts', { device: v.device, root: String(v.root), count: v.keyslots, version: v.luks_version ?? 2,
    escrowed: String(v.escrowed) })
}

async function load(): Promise<void> {
  const d = await getDisk(props.deviceId)
  if (typeof d === 'string') {
    problem.value = d
    return
  }
  disk.value = d
  const c = d.disk_conversion
  abortAt.value = c && c.abort_command_id && abortOpen(c) ? await abortIssuedAt(props.deviceId, c.abort_command_id) : null
}

/** A catalog text, or the device's own word where the catalog has none (a newer agent's reason). */
function known(key: string, value: string): string {
  return te(key) ? t(key) : value
}

const at = (iso: string | null | undefined) => (iso ? formatDateTime(iso, locale.value) : '–')

/** The line of the conversion's phase (plan M8e decision 25). */
const phaseText = computed(() => {
  const c = conversion.value
  if (!c) return ''
  switch (c.phase) {
    case 'requested':
      return t('devices.disk.convert.phases.requested', { status: known('commands.statuses.' + c.command_status, c.command_status) })
    case 'prepared':
      return t('devices.disk.convert.phases.prepared', {
        at: at(health.value?.phase === 'prepared' && health.value.updated_at ? health.value.updated_at : c.requested_at),
      })
    case 'encrypting':
      return t('devices.disk.convert.phases.encrypting', {
        percent: conversionPercent(c), total: formatGB(c.data_bytes ?? 0, locale.value) ?? '–',
      })
    case 'completed':
      return t('devices.disk.convert.phases.completed', { at: at(c.finished_at ?? c.progress_at) })
    case 'cancelled':
      return t('devices.disk.convert.phases.cancelled', { at: at(c.finished_at) })
    default:
      return ''
  }
})

/** The ETA or the pause reason and the time of the last progress report. */
const progressText = computed(() => {
  const c = conversion.value
  if (!c) return ''
  const parts = [
    c.paused_reason
      ? known('devices.disk.convert.paused.' + c.paused_reason, c.paused_reason)
      : c.eta_s !== null ? t('devices.disk.convert.eta', { duration: formatDuration(c.eta_s, locale.value) }) : '',
    c.progress_at ? t('devices.disk.convert.progressAt', { at: at(c.progress_at) }) : '',
  ]
  return parts.filter(Boolean).join(' · ')
})

/** The preparation's wait for a package run (plan M8e amendment 2026-10-21, item 18); empty without one. */
const waitText = computed(() => {
  const c = conversion.value
  if (c?.phase !== 'requested' || !c.paused_reason) return ''
  if (c.paused_reason === 'packages_busy' && c.paused_since) return t('devices.disk.convert.packagesBusy', { at: at(c.paused_since) })
  return known('devices.disk.convert.paused.' + c.paused_reason, c.paused_reason)
})

/** Why the device's initrd work cannot go on (plan M8e amendment 2026-10-21, item 19); an unknown code as reported. */
const initrdIssueText = computed(() => {
  const c = conversion.value
  if (!c?.initrd_issue) return ''
  const key = 'devices.disk.convert.initrdIssues.' + c.initrd_issue
  if (!te(key)) return c.initrd_issue
  return t(key, {
    kernel: c.initrd_issue_kernel ?? '–',
    needed: formatMiB(c.boot_space_needed ?? 0, locale.value, Math.ceil),
    free: formatMiB(c.boot_space_free ?? 0, locale.value, Math.floor),
  })
})


/** Both actions start with a step-up; the page continues in resume() when the browser comes back. A header download
 * carries the volume (null: the root volume). */
function start(action: Action, volume: string | null = null): void {
  problem.value = ''
  startStepUp(action, props.deviceId, volume)
}

async function resume(): Promise<void> {
  for (const action of ['disk-recovery-key', 'disk-header', 'disk-convert', 'disk-convert-cancel'] as Action[]) {
    const resumed = resumeStepUp<string | null>(action, props.deviceId)
    if (!resumed) continue
    await router.replace(withoutStepUpParam())
    if (resumed.failed) {
      problem.value = 'step_up_failed'
      return
    }
    if (action === 'disk-recovery-key') await showRecoveryKey()
    else if (action === 'disk-convert') encryptOpen.value = true
    else if (action === 'disk-convert-cancel') await cancelConversion()
    else await saveHeader(typeof resumed.payload === 'string' ? resumed.payload : null)
    return
  }
}

async function showRecoveryKey(): Promise<void> {
  const confirmed = await confirm({
    title: t('devices.disk.recoveryKey.title'), message: t('devices.disk.recoveryKey.confirm', { hostname: props.hostname }),
    confirmLabel: t('devices.disk.recoveryKey.label'), destructive: true, requireTypedText: props.hostname,
  })
  if (!confirmed) return
  const res = await revealRecoveryKey(props.deviceId, props.hostname)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  revealed.value = res
  remaining.value = hideAfter
  clearInterval(timer)
  timer = setInterval(() => {
    remaining.value -= 1
    if (remaining.value <= 0) hide()
  }, 1000)
}

async function saveHeader(volume: string | null): Promise<void> {
  const device = volumes.value.find((v) => volume ? v.uuid === volume : v.root)?.device ?? t('devices.disk.rootVolume')
  const confirmed = await confirm({
    title: t('devices.disk.header.title'), message: t('devices.disk.header.confirm', { hostname: props.hostname, device }),
    confirmLabel: t('devices.disk.header.label'), destructive: true, requireTypedText: props.hostname,
  })
  if (!confirmed) return
  const res = await downloadHeader(props.deviceId, props.hostname, volume)
  if (typeof res === 'string') problem.value = res
  else saveFile(res)
}

async function submitEncrypt(reason: string): Promise<void> {
  encryptOpen.value = false
  notice.value = ''
  const res = await requestEncrypt(props.deviceId, props.hostname, reason)
  if (res) problem.value = res
  else notice.value = 'requested'
  await load()
}

async function cancelConversion(): Promise<void> {
  notice.value = ''
  const confirmed = await confirm({
    title: t('devices.disk.convert.cancel.title', { hostname: props.hostname }), message: t('devices.disk.convert.cancel.confirm'),
    confirmLabel: t('devices.disk.convert.cancel.confirmLabel'), destructive: true, requireTypedText: props.hostname,
  })
  if (!confirmed) return
  const res = await cancelEncrypt(props.deviceId, props.hostname)
  if (res) problem.value = res
  await load()
  if (!res && conversion.value?.phase === 'cancelled') notice.value = 'cancelled'
}

function hide(): void {
  clearInterval(timer)
  timer = undefined
  revealed.value = null
  copied.value = false
}

async function copy(key: string): Promise<void> {
  await navigator.clipboard.writeText(key)
  copied.value = true
}

onMounted(async () => {
  await load()
  await resume()
})
onBeforeUnmount(hide)
</script>

<template>
  <section
    class="pd-panel disk-encryption"
    data-testid="disk-encryption"
    aria-labelledby="device-disk-title"
  >
    <header class="pd-panel-header">
      <h2
        id="device-disk-title"
        class="pd-type-section"
      >
        {{ t('devices.disk.title') }}
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
      <template v-if="disk">
        <v-alert
          v-if="disk.last_keyslot_change"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="disk-keyslot-change"
        >
          {{ t('devices.disk.keyslotChange', {
            at: formatDateTime(disk.last_keyslot_change.at, locale),
            before: disk.last_keyslot_change.before.join(', '),
            after: disk.last_keyslot_change.after.join(', '),
          }) }}
        </v-alert>
        <v-alert
          v-if="disk.state === 'not_encrypted' && health?.eligible && !conversionOpen(conversion)"
          type="info"
          variant="tonal"
          class="conflict"
          data-testid="disk-convert-eligible"
        >
          {{ t('devices.disk.convert.eligible') }}
        </v-alert>
        <v-alert
          v-else-if="disk.state === 'not_encrypted' || disk.state === 'unmanaged'"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="disk-reinstall"
        >
          <template v-if="disk.state === 'unmanaged'">
            {{ t('devices.disk.unmanaged.reinstall') }}
          </template>
          <template v-else>
            <p>{{ t('devices.disk.notEncrypted.reinstall') }}</p>
            <template v-if="health && !health.eligible && (health.reasons ?? []).length > 0">
              <p>{{ t('devices.disk.convert.reasonsTitle') }}</p>
              <ul data-testid="disk-convert-reasons">
                <li
                  v-for="r in health.reasons"
                  :key="r"
                >
                  {{ known('devices.disk.convert.reasons.' + r, r) }}
                </li>
              </ul>
            </template>
          </template>
        </v-alert>
        <v-alert
          v-if="keyOnBoot"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="disk-convert-key-on-boot"
        >
          {{ t('devices.disk.convert.keyOnBoot') }}
        </v-alert>
        <div
          v-if="showConversion && conversion"
          class="pd-conversion"
          data-testid="disk-conversion"
        >
          <v-alert
            v-if="conversion.phase === 'failed'"
            type="error"
            variant="tonal"
            class="conflict"
            data-testid="disk-convert-failed"
          >
            {{ t('devices.disk.convert.failed', {
              stage: known('devices.disk.convert.failures.' + (conversion.failure_stage ?? ''), conversion.failure_stage ?? ''),
              reason: conversion.failure_reason ?? '',
            }) }}
            <a
              :href="conversionRunbook"
              target="_blank"
              rel="noopener"
            >{{ t('devices.disk.convert.runbook') }}</a>
          </v-alert>
          <template v-else>
            <p data-testid="disk-convert-phase">
              {{ phaseText }}
            </p>
            <template v-if="conversion.phase === 'encrypting'">
              <v-progress-linear
                :model-value="conversionPercent(conversion)"
                :aria-label="phaseText"
                color="primary"
                height="8"
                rounded
                data-testid="disk-convert-progress"
              />
              <p
                v-if="progressText"
                class="pd-type-caption"
                data-testid="disk-convert-progress-text"
              >
                {{ progressText }}
              </p>
              <p
                v-if="health?.enrollment_deferred === 'reencrypt'"
                class="pd-type-caption"
                data-testid="disk-convert-enrollment-deferred"
              >
                {{ t('devices.disk.convert.enrollmentDeferred') }}
              </p>
            </template>
            <v-alert
              v-if="conversion.phase === 'completed' && health?.enrollment_deferred === 'reencrypt_after_completed'"
              type="warning"
              variant="tonal"
              class="conflict"
              data-testid="disk-convert-enrollment-refused"
            >
              {{ t('devices.disk.convert.enrollmentDeferredAfterCompleted') }}
            </v-alert>
          </template>
          <p
            v-if="waitText"
            class="pd-type-caption"
            data-testid="disk-convert-wait"
          >
            {{ waitText }}
          </p>
          <v-alert
            v-if="initrdIssueText"
            :type="conversion.initrd_issue === 'orphan_initrd_removed' ? 'info' : 'warning'"
            variant="tonal"
            class="conflict"
            data-testid="disk-convert-initrd-issue"
          >
            {{ initrdIssueText }}
          </v-alert>
          <v-alert
            v-if="conversion.cleanup_error"
            type="warning"
            variant="tonal"
            class="conflict"
            data-testid="disk-convert-cleanup"
          >
            {{ t('devices.disk.convert.cleanupPending', { reason: conversion.cleanup_error }) }}
            <a
              :href="conversionRunbook"
              target="_blank"
              rel="noopener"
            >{{ t('devices.disk.convert.runbook') }}</a>
          </v-alert>
          <p
            v-if="cancelSent"
            role="status"
            data-testid="disk-convert-cancel-sent"
          >
            {{ t('devices.disk.convert.cancelSent', { at: at(abortAt) }) }}
          </p>
          <p
            v-if="conversion.abort_refused_reason && conversion.phase !== 'cancelled'"
            data-testid="disk-convert-cancel-refused"
          >
            {{ t('devices.disk.convert.cancelRefused', {
              reason: known('devices.disk.convert.abortReasons.' + conversion.abort_refused_reason, conversion.abort_refused_reason),
            }) }}
          </p>
        </div>
        <p
          v-if="notice"
          role="status"
          data-testid="disk-convert-notice"
        >
          {{ t('devices.disk.convert.' + notice) }}
        </p>
        <v-alert
          v-if="disk.state === 'unlock_mode_mismatch'"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="disk-unlock-mode-mismatch"
        >
          {{ t('devices.disk.states.unlock_mode_mismatch') }}
          <a
            :href="unlockModeRunbook"
            target="_blank"
            rel="noopener"
          >{{ t('devices.disk.unlockModeRunbook') }}</a>
        </v-alert>
        <dl class="pd-facts">
          <div>
            <dt>
              {{ t('devices.disk.state') }}
            </dt>
            <dd data-testid="disk-state">
              {{ disk.state ? t(diskStateLabel(disk.state)) : t('devices.disk.notReported') }}
            </dd>
          </div>
          <div v-if="disk.unlock_mode">
            <dt>
              {{ t('devices.disk.unlockMode') }}
            </dt>
            <dd data-testid="disk-unlock-mode">
              {{ t('devices.disk.unlockModes.' + disk.unlock_mode) }}
            </dd>
          </div>
          <div v-if="disk.state">
            <dt>
              {{ t('devices.disk.keyslots') }}
            </dt>
            <dd data-testid="disk-tokens">
              {{ t('devices.disk.keyslotFacts', { count: disk.keyslots, kinds: disk.tokens.join(', '), version: disk.luks_version ?? 2 }) }}
            </dd>
          </div>
          <div v-if="disk.reported_at">
            <dt>
              {{ t('devices.disk.reportedAt') }}
            </dt>
            <dd>{{ formatDateTime(disk.reported_at, locale) }}</dd>
          </div>
          <div>
            <dt>
              {{ t('devices.disk.recoveryKeyRow') }}
            </dt>
            <dd data-testid="disk-recovery">
              {{ recovery ? t('devices.disk.escrowFacts', { generation: recovery.generation, at: formatDateTime(recovery.created_at, locale) }) : t('devices.disk.none') }}
            </dd>
          </div>
          <div v-if="volumes.length > 0 || disk.unresolved.length > 0">
            <dt>
              {{ t('devices.disk.volumes') }}
            </dt>
            <dd data-testid="disk-volumes">
              <div
                v-for="(v, i) in volumes"
                :key="'v' + i"
                data-testid="disk-volume"
              >
                {{ volumeText(v) }}
              </div>
              <div
                v-for="(source, i) in disk.unresolved"
                :key="'u' + i"
              >
                {{ t('devices.disk.unresolved', { source }) }}
              </div>
            </dd>
          </div>
          <div>
            <dt>
              {{ t('devices.disk.headers') }}
            </dt>
            <dd data-testid="disk-headers">
              <span v-if="headers.length === 0">{{ t('devices.disk.none') }}</span>
              <div
                v-for="h in headers"
                :key="h.generation"
              >
                <template v-if="volumes.length > 1">
                  {{ t('devices.disk.headerVolumeFacts', { device: headerDevice(h, volumes), generation: h.generation, status: t('devices.disk.escrowStatuses.' + h.status), at: formatDateTime(h.created_at, locale) }) }}
                </template>
                <template v-else>
                  {{ t('devices.disk.headerFacts', { generation: h.generation, status: t('devices.disk.escrowStatuses.' + h.status), at: formatDateTime(h.created_at, locale) }) }}
                </template>
              </div>
            </dd>
          </div>
        </dl>
        <div
          v-if="session.canDelete"
          class="form-actions"
        >
          <v-btn
            v-if="canEncrypt"
            color="error"
            data-testid="disk-convert"
            @click="start('disk-convert')"
          >
            {{ t('devices.disk.convert.label') }}
          </v-btn>
          <v-btn
            v-if="canCancel"
            variant="outlined"
            data-testid="disk-convert-cancel"
            @click="start('disk-convert-cancel')"
          >
            {{ t('devices.disk.convert.cancel.label') }}
          </v-btn>
          <v-btn
            v-if="recovery"
            color="error"
            data-testid="disk-reveal"
            @click="start('disk-recovery-key')"
          >
            {{ t('devices.disk.recoveryKey.label') }}
          </v-btn>
          <template v-if="downloadable.length > 0">
            <v-btn
              v-for="v in downloadable"
              :key="v.uuid"
              variant="outlined"
              data-testid="disk-header"
              @click="start('disk-header', v.root ? null : v.uuid ?? null)"
            >
              {{ t('devices.disk.header.volumeLabel', { device: v.device }) }}
            </v-btn>
          </template>
          <v-btn
            v-else-if="header"
            variant="outlined"
            data-testid="disk-header"
            @click="start('disk-header')"
          >
            {{ t('devices.disk.header.label') }}
          </v-btn>
        </div>
      </template>
    </div>
    <EncryptDiskDialog
      :model-value="encryptOpen"
      :hostname="hostname"
      :tpm-only="disk?.unlock_mode === 'tpm_only'"
      :initramfs="health?.initramfs"
      :initramfs-removes="health?.initramfs_removes ?? []"
      :estimate="conversionEstimate(diskTotalBytes)"
      @confirm="submitEncrypt"
      @cancel="encryptOpen = false"
    />
    <v-dialog
      :model-value="revealed !== null"
      max-width="40rem"
      persistent
      aria-labelledby="recovery-key-title"
    >
      <v-card data-testid="recovery-key-dialog">
        <v-card-title
          id="recovery-key-title"
          tag="h2"
        >
          {{ t('devices.disk.revealed.title', { hostname }) }}
        </v-card-title>
        <v-card-text>
          <p>{{ t('devices.disk.revealed.hint', { seconds: remaining }) }}</p>
          <p>{{ t('devices.disk.revealed.usage') }}</p>
          <v-text-field
            :model-value="revealed?.recovery_key ?? ''"
            :label="t('devices.disk.revealed.generation', { generation: revealed?.generation ?? 0 })"
            readonly
            autocomplete="off"
            spellcheck="false"
            class="mono"
            data-testid="recovery-key"
          />
          <div class="form-actions">
            <v-btn
              variant="tonal"
              data-testid="recovery-key-copy"
              @click="copy(revealed?.recovery_key ?? '')"
            >
              {{ copied ? t('devices.disk.revealed.copied') : t('devices.disk.revealed.copy') }}
            </v-btn>
            <v-btn
              color="primary"
              data-testid="recovery-key-close"
              @click="hide"
            >
              {{ t('devices.disk.revealed.close') }}
            </v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
