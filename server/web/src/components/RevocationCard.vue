<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { RevocationRequest } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { listRevocations, requestRevocation, timeline, type RevokeAction } from '../lib/revocations'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * Lock and Destroy of a device (plan M4c decision 18): the reason, a step-up, the typed hostname, then the request;
 * below it the revocation timeline of the device's latest requests. A Destroy waits for a second administrator.
 */
const props = defineProps<{ deviceId: string; hostname: string; revocable: boolean; presumedSelfLockedAt: string | null }>()

const { t, locale } = useI18n()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()

const reason = ref('')
const problem = ref('')
const requested = ref<RevocationRequest | null>(null)
const requests = ref<RevocationRequest[]>([])

const stepUpAction = (action: RevokeAction) => 'revocation-' + action

async function load(): Promise<void> {
  try {
    const page = await listRevocations(props.deviceId)({ page: 1, page_size: 10, sort: '-requested_at' })
    requests.value = page.items
  } catch {
    // Operators and auditors may not list revocations; the timeline stays empty.
    requests.value = []
  }
}

/** The request starts with a step-up; the reason waits in the step-up's pending action (it is not a secret). */
function start(action: RevokeAction): void {
  problem.value = ''
  requested.value = null
  startStepUp(stepUpAction(action), props.deviceId, { reason: reason.value.trim() })
}

async function resume(): Promise<void> {
  for (const action of ['lock', 'destroy'] as RevokeAction[]) {
    const resumed = resumeStepUp<{ reason: string }>(stepUpAction(action), props.deviceId)
    if (!resumed) continue
    await router.replace(withoutStepUpParam())
    if (resumed.failed) {
      problem.value = 'step_up_failed'
      return
    }
    reason.value = resumed.payload.reason
    await revoke(action)
    return
  }
}

async function revoke(action: RevokeAction): Promise<void> {
  const key = 'devices.revocation.' + action
  const confirmed = await confirm({
    title: t(key + '.title'), message: t(key + '.confirm', { hostname: props.hostname }), confirmLabel: t(key + '.label'),
    destructive: true, requireTypedText: props.hostname,
  })
  if (!confirmed) return
  const res = await requestRevocation(props.deviceId, action, props.hostname, reason.value.trim())
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  requested.value = res
  reason.value = ''
  await load()
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
    class="revocation"
    data-testid="revocation"
  >
    <h2>{{ t('devices.revocation.title') }}</h2>
    <v-alert
      v-if="presumedSelfLockedAt"
      type="warning"
      variant="tonal"
      class="conflict"
      data-testid="presumed-self-locked"
    >
      {{ t('devices.revocation.presumedSelfLocked', { at: formatDateTime(presumedSelfLockedAt, locale) }) }}
    </v-alert>
    <v-alert
      v-if="!session.me?.revocation_enabled"
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="revocation-disabled"
    >
      {{ t('revocations.disabled') }}
    </v-alert>
    <template v-else-if="revocable">
      <p class="summary">
        {{ t('devices.revocation.hint') }}
      </p>
      <v-text-field
        id="revocation-reason"
        v-model="reason"
        :label="t('devices.revocation.reason')"
        :hint="t('devices.revocation.reasonHint')"
        persistent-hint
        counter="500"
        maxlength="500"
        autocomplete="off"
      />
      <div class="form-actions">
        <v-btn
          color="error"
          variant="outlined"
          data-testid="revocation-destroy"
          @click="start('destroy')"
        >
          {{ t('devices.revocation.destroy.label') }}
        </v-btn>
        <v-btn
          color="error"
          data-testid="revocation-lock"
          @click="start('lock')"
        >
          {{ t('devices.revocation.lock.label') }}
        </v-btn>
      </div>
    </template>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <p
      v-if="requested"
      role="status"
      data-testid="revocation-requested"
    >
      {{ t('devices.revocation.requested.' + (requested.action === 'destroy' ? 'destroy' : 'lock')) }}
    </p>
    <v-table
      v-if="requests.length > 0"
      class="table"
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
            {{ t('revocations.statuses.' + r.status) }}
            <span v-if="r.rejection">({{ r.rejection }})</span>
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
          </td>
        </tr>
      </tbody>
    </v-table>
  </section>
</template>
