<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { LocalAdmin, LocalAdminRevealed } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { formatDateTime } from '../lib/format'
import { getLocalAdmin, revealLocalAdmin, rotateLocalAdmin, rotationOverdue } from '../lib/localAdmin'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The managed local administrator of a device (plan M4a decision 20): state and generations, Rotate now, and
 * Reveal — a step-up, then the typed hostname, then the passwords in a dialog that hides them after 60 s. The
 * passwords live only in this component while the dialog is open: never in the store or the URL.
 */
const props = defineProps<{ deviceId: string; hostname: string; active: boolean }>()
const emit = defineEmits<{ changed: [] }>()

/** Seconds until revealed passwords are hidden. */
const hideAfter = 60

const { t, locale } = useI18n()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()

const state = ref<LocalAdmin | null>(null)
const problem = ref('')
const notice = ref('')
const revealed = ref<LocalAdminRevealed | null>(null)
const remaining = ref(hideAfter)
const copied = ref<number | null>(null)
let timer: ReturnType<typeof setInterval> | undefined

const overdue = computed(() => state.value !== null && rotationOverdue(state.value, new Date()))

async function load(): Promise<void> {
  const s = await getLocalAdmin(props.deviceId)
  if (typeof s === 'string') problem.value = s
  else state.value = s
}

/** Reveal starts with a step-up; the page continues in resume() when the browser comes back. */
function reveal(): void {
  problem.value = ''
  startStepUp('reveal', props.deviceId)
}

async function resume(): Promise<void> {
  const resumed = resumeStepUp<null>('reveal', props.deviceId)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  const confirmed = await confirm({
    title: t('devices.localAdmin.reveal.title'), message: t('devices.localAdmin.reveal.confirm', { hostname: props.hostname }),
    confirmLabel: t('devices.localAdmin.reveal.label'), destructive: true, requireTypedText: props.hostname,
  })
  if (!confirmed) return
  const res = await revealLocalAdmin(props.deviceId, props.hostname)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  show(res)
  emit('changed')
}

function show(res: LocalAdminRevealed): void {
  revealed.value = res
  remaining.value = hideAfter
  clearInterval(timer)
  timer = setInterval(() => {
    remaining.value -= 1
    if (remaining.value <= 0) hide()
  }, 1000)
}

function hide(): void {
  clearInterval(timer)
  timer = undefined
  revealed.value = null
  copied.value = null
}

async function copy(generation: number, password: string): Promise<void> {
  await navigator.clipboard.writeText(password)
  copied.value = generation
}

async function rotate(): Promise<void> {
  problem.value = ''
  notice.value = ''
  const confirmed = await confirm({
    title: t('devices.localAdmin.rotate.title'), message: t('devices.localAdmin.rotate.confirm', { hostname: props.hostname }),
    confirmLabel: t('devices.localAdmin.rotate.label'),
  })
  if (!confirmed) return
  problem.value = (await rotateLocalAdmin(props.deviceId)) ?? ''
  if (!problem.value) notice.value = t('devices.localAdmin.rotate.requested')
  emit('changed')
  await load()
}

onMounted(async () => {
  await load()
  await resume()
})
onBeforeUnmount(hide)
</script>

<template>
  <section
    class="local-admin"
    data-testid="local-admin"
  >
    <h2>{{ t('devices.localAdmin.title') }}</h2>
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
        v-if="overdue"
        type="warning"
        variant="tonal"
        class="conflict"
        data-testid="local-admin-overdue"
      >
        {{ t('devices.localAdmin.overdue') }}
      </v-alert>
      <v-alert
        v-if="state.last_rotation_error"
        type="warning"
        variant="tonal"
        class="conflict"
        data-testid="local-admin-error"
      >
        {{ t('devices.localAdmin.lastError', {
          generation: state.last_rotation_error.generation,
          reason: t('devices.localAdmin.errors.' + state.last_rotation_error.reason),
          at: formatDateTime(state.last_rotation_error.at, locale),
        }) }}
      </v-alert>
      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('devices.localAdmin.account') }}
            </th>
            <td>{{ state.username }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.localAdmin.active') }}
            </th>
            <td data-testid="local-admin-active">
              {{ state.active_generation ?? t('devices.localAdmin.none') }}
            </td>
          </tr>
          <tr v-if="state.pending_generation !== null">
            <th scope="row">
              {{ t('devices.localAdmin.pending') }}
            </th>
            <td>{{ state.pending_generation }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.localAdmin.lastRotated') }}
            </th>
            <td>{{ state.last_rotated_at ? formatDateTime(state.last_rotated_at, locale) : t('devices.never') }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.localAdmin.nextRotation') }}
            </th>
            <td>{{ state.next_rotation_at ? formatDateTime(state.next_rotation_at, locale) : '–' }}</td>
          </tr>
        </tbody>
      </v-table>
      <div class="form-actions">
        <v-btn
          v-if="session.canWrite && active"
          variant="outlined"
          data-testid="local-admin-rotate"
          @click="rotate"
        >
          {{ t('devices.localAdmin.rotate.label') }}
        </v-btn>
        <v-btn
          v-if="session.canDelete && state.active_generation !== null"
          color="error"
          data-testid="local-admin-reveal"
          @click="reveal"
        >
          {{ t('devices.localAdmin.reveal.label') }}
        </v-btn>
      </div>
    </template>
    <v-dialog
      :model-value="revealed !== null"
      max-width="36rem"
      persistent
      aria-labelledby="revealed-title"
    >
      <v-card data-testid="revealed-dialog">
        <v-card-title
          id="revealed-title"
          tag="h2"
        >
          {{ t('devices.localAdmin.revealed.title', { username: state?.username ?? '' }) }}
        </v-card-title>
        <v-card-text>
          <p>{{ t('devices.localAdmin.revealed.hint', { seconds: remaining }) }}</p>
          <div
            v-for="p in revealed?.passwords ?? []"
            :key="p.generation"
            class="revealed-password"
          >
            <v-text-field
              :model-value="p.password"
              :label="t('devices.localAdmin.revealed.generation', { generation: p.generation, state: t('devices.localAdmin.revealed.states.' + p.state) })"
              readonly
              autocomplete="off"
              spellcheck="false"
              class="mono"
              :data-testid="'revealed-' + p.state"
            />
            <v-btn
              variant="tonal"
              :data-testid="'copy-' + p.state"
              @click="copy(p.generation, p.password)"
            >
              {{ copied === p.generation ? t('devices.localAdmin.revealed.copied') : t('devices.localAdmin.revealed.copy') }}
            </v-btn>
          </div>
          <div class="form-actions">
            <v-btn
              color="primary"
              data-testid="revealed-close"
              @click="hide"
            >
              {{ t('devices.localAdmin.revealed.close') }}
            </v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
