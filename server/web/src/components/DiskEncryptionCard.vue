<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { DiskEncryption, DiskRecoveryKey, DiskVolume } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { downloadHeader, getDisk, headerDevice, latestStored, revealRecoveryKey, saveFile, volumeHeaders } from '../lib/disk'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The disk encryption of a device (plan M4b decision 14): state, keyslots, every LUKS volume (PDK-009), escrowed
 * generations, the last keyslot change, and for organization administrators the recovery key and the header of each
 * volume — each after a step-up and the typed hostname. The recovery key lives only in this component while its
 * dialog is open and is hidden after 60 s.
 */
const props = defineProps<{ deviceId: string; hostname: string }>()

/** Seconds until a revealed recovery key is hidden. */
const hideAfter = 60

type Action = 'disk-recovery-key' | 'disk-header'

const { t, locale } = useI18n()
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

const recovery = computed(() => (disk.value ? latestStored(disk.value.recovery_keys) : null))
const header = computed(() => (disk.value ? latestStored(disk.value.headers) : null))
const headers = computed(() => disk.value?.headers.slice(0, 5) ?? [])
const volumes = computed(() => disk.value?.volumes ?? [])
/** The volumes with a stored header to download; empty for a device that reports no volumes (before PDK-009). */
const downloadable = computed(() => volumes.value.filter((v) => v.uuid && latestStored(volumeHeaders(disk.value?.headers ?? [], v))))

function volumeText(v: DiskVolume): string {
  if (!v.uuid) return t('devices.disk.volumeUnknown', { device: v.device })
  return t('devices.disk.volumeFacts', { device: v.device, root: String(v.root), count: v.keyslots, version: v.luks_version ?? 2,
    escrowed: String(v.escrowed) })
}

async function load(): Promise<void> {
  const d = await getDisk(props.deviceId)
  if (typeof d === 'string') problem.value = d
  else disk.value = d
}

/** Both actions start with a step-up; the page continues in resume() when the browser comes back. A header download
 * carries the volume (null: the root volume). */
function start(action: Action, volume: string | null = null): void {
  problem.value = ''
  startStepUp(action, props.deviceId, volume)
}

async function resume(): Promise<void> {
  for (const action of ['disk-recovery-key', 'disk-header'] as Action[]) {
    const resumed = resumeStepUp<string | null>(action, props.deviceId)
    if (!resumed) continue
    await router.replace(withoutStepUpParam())
    if (resumed.failed) {
      problem.value = 'step_up_failed'
      return
    }
    if (action === 'disk-recovery-key') await showRecoveryKey()
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
    class="disk-encryption"
    data-testid="disk-encryption"
  >
    <h2>{{ t('devices.disk.title') }}</h2>
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
      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('devices.disk.state') }}
            </th>
            <td data-testid="disk-state">
              {{ disk.state ? t('devices.disk.states.' + disk.state) : t('devices.disk.notReported') }}
            </td>
          </tr>
          <tr v-if="disk.state">
            <th scope="row">
              {{ t('devices.disk.keyslots') }}
            </th>
            <td data-testid="disk-tokens">
              {{ t('devices.disk.keyslotFacts', { count: disk.keyslots, kinds: disk.tokens.join(', '), version: disk.luks_version ?? 2 }) }}
            </td>
          </tr>
          <tr v-if="disk.reported_at">
            <th scope="row">
              {{ t('devices.disk.reportedAt') }}
            </th>
            <td>{{ formatDateTime(disk.reported_at, locale) }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.disk.recoveryKeyRow') }}
            </th>
            <td data-testid="disk-recovery">
              {{ recovery ? t('devices.disk.escrowFacts', { generation: recovery.generation, at: formatDateTime(recovery.created_at, locale) }) : t('devices.disk.none') }}
            </td>
          </tr>
          <tr v-if="volumes.length > 0 || disk.unresolved.length > 0">
            <th scope="row">
              {{ t('devices.disk.volumes') }}
            </th>
            <td data-testid="disk-volumes">
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
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.disk.headers') }}
            </th>
            <td data-testid="disk-headers">
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
            </td>
          </tr>
        </tbody>
      </v-table>
      <div
        v-if="session.canDelete"
        class="form-actions"
      >
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
