<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useConfirm } from '../composables/useConfirm'
import { useProblemText } from '../lib/problems'
import { endAllConfirmation, endAllSessions } from '../lib/sessions'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'

const stepUpAction = 'sessions-end-all'

const { t } = useI18n()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const problem = ref('')
const busy = ref(false)

onMounted(async () => {
  const resumed = resumeStepUp<null>(stepUpAction, stepUpAction)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  await run(false)
})

/** Ends every session; the own session ends too, so the browser goes back to the login. */
async function run(stepUp: boolean): Promise<void> {
  problem.value = ''
  busy.value = true
  const res = await endAllSessions()
  busy.value = false
  if (typeof res === 'number') {
    window.location.assign('/')
    return
  }
  if (res === stepUpRequired && stepUp) {
    startStepUp(stepUpAction, stepUpAction)
    return
  }
  problem.value = res
}

async function onEndAll(): Promise<void> {
  const confirmed = await confirm({
    title: t('sessions.confirmTitle'),
    message: t('sessions.confirmMessage'),
    confirmLabel: t('sessions.endAll'),
    destructive: true,
    requireTypedText: endAllConfirmation,
  })
  if (!confirmed) return
  await run(true)
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('sessions.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('sessions.summary') }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <v-btn
      color="error"
      :loading="busy"
      data-testid="end-all-sessions"
      @click="onEndAll"
    >
      {{ t('sessions.endAll') }}
    </v-btn>
  </section>
</template>
