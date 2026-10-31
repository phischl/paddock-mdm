<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { usePending } from '../composables/usePending'
import {
  getPseudonymLookup, isProblem, listPseudonymizing, pollUntil, pseudonymPattern, requestPseudonym,
  type NotificationDestination,
} from '../lib/notifications'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useRouter } from 'vue-router'

/**
 * Resolves a pseudonym of the organization's notifications to a user name (plan M9 decision 36): the notifier answers
 * in its next round, so the result is polled. Needs a step-up, which sends the browser away and back.
 */
const emit = defineEmits<{ close: [] }>()

const stepUpAction = 'notification-resolve'
const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const router = useRouter()

const destinations = ref<NotificationDestination[]>([])
const destinationId = ref('')
const pseudonym = ref('')
const touched = ref(false)
const problem = ref('')
const waiting = ref(false)
const result = ref<{ username: string } | null>(null)
const timedOut = ref(false)
let cancelled = false

const invalid = computed(() => touched.value && !pseudonymPattern.test(pseudonym.value.trim()))

onMounted(async () => {
  destinations.value = await listPseudonymizing()
  destinationId.value = destinations.value[0]?.id ?? ''
  const resumed = resumeStepUp<{ id: string; pseudonym: string }>(stepUpAction, stepUpAction)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  pseudonym.value = resumed.payload.pseudonym
  destinationId.value = resumed.payload.id
  await resolve(false)
})
onBeforeUnmount(() => { cancelled = true })

async function resolve(stepUp: boolean): Promise<void> {
  problem.value = ''
  result.value = null
  timedOut.value = false
  const value = pseudonym.value.trim()
  const lookup = await requestPseudonym(destinationId.value, value)
  if (isProblem(lookup)) {
    if (lookup.code === stepUpRequired && stepUp) {
      startStepUp(stepUpAction, stepUpAction, { id: destinationId.value, pseudonym: value })
      return
    }
    problem.value = lookup.code
    return
  }
  waiting.value = true
  const answer = await pollUntil(async () => {
    const r = await getPseudonymLookup(destinationId.value, lookup)
    if (isProblem(r)) {
      problem.value = r.code
      return { username: '', failed: true }
    }
    return r.resolved ? { username: r.username, failed: false } : null
  }, () => cancelled)
  waiting.value = false
  if (answer === null) timedOut.value = true
  else if (!answer.failed) result.value = { username: answer.username }
}

async function submit(): Promise<void> {
  touched.value = true
  if (!pseudonymPattern.test(pseudonym.value.trim()) || !destinationId.value) return
  await resolve(true)
}
</script>

<template>
  <v-dialog
    :model-value="true"
    max-width="36rem"
    :aria-label="t('notifications.pseudonym.title')"
    persistent
  >
    <v-card
      :title="t('notifications.pseudonym.title')"
      data-testid="notification-pseudonym-dialog"
      @keydown.esc.stop="emit('close')"
    >
      <v-card-text>
        <p class="summary">
          {{ t('notifications.pseudonym.summary') }}
        </p>
        <v-alert
          v-if="destinations.length === 0"
          type="info"
          variant="tonal"
          data-testid="pseudonym-none"
        >
          {{ t('notifications.pseudonym.none') }}
        </v-alert>
        <form
          v-else
          class="form"
          novalidate
          @submit.prevent="run(submit)"
        >
          <v-select
            v-if="destinations.length > 1"
            v-model="destinationId"
            :label="t('notifications.pseudonym.destination')"
            :items="destinations"
            item-title="name"
            item-value="id"
          />
          <v-text-field
            id="notification-pseudonym"
            v-model="pseudonym"
            :label="t('notifications.pseudonym.label')"
            :hint="t('notifications.pseudonym.hint')"
            persistent-hint
            autocomplete="off"
            spellcheck="false"
            :error-messages="invalid ? [t('notifications.pseudonym.invalid')] : []"
          />
          <p
            v-if="problem"
            class="form-error"
            role="alert"
          >
            {{ problemText(problem) }}
          </p>
          <p
            v-if="waiting"
            role="status"
            data-testid="pseudonym-waiting"
          >
            {{ t('notifications.pseudonym.waiting') }}
          </p>
          <p
            v-if="result"
            role="status"
            data-testid="pseudonym-result"
          >
            {{ result.username === '' ? t('notifications.pseudonym.noMatch') : t('notifications.pseudonym.match', { username: result.username }) }}
          </p>
          <p
            v-if="timedOut"
            role="status"
            data-testid="pseudonym-timeout"
          >
            {{ t('notifications.pseudonym.timeout') }}
          </p>
          <div class="form-actions">
            <v-btn
              type="submit"
              color="primary"
              :loading="pending || waiting"
              :disabled="pending || waiting"
              data-testid="pseudonym-submit"
            >
              {{ t('notifications.pseudonym.resolve') }}
            </v-btn>
          </div>
        </form>
        <div class="form-actions">
          <v-btn
            variant="tonal"
            data-testid="pseudonym-close"
            @click="emit('close')"
          >
            {{ t('notifications.close') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
