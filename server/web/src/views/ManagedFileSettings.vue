<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useConfirm } from '../composables/useConfirm'
import { getOperatorRoots, setOperatorRoots } from '../lib/managedConfig'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/**
 * The operator roots of the managed files (ADR 0034 amendment 2026-10-16): below them operators manage files without
 * a step-up; every other path needs an organization administrator with a step-up. Changing them needs a step-up.
 */
const { t } = useI18n()
const { pending, run } = usePending()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const text = ref('')
const problem = ref('')
const saved = ref(false)

function lines(): string[] {
  return text.value.split('\n').map((l) => l.trim()).filter((l) => l !== '')
}

async function load(): Promise<void> {
  const r = await getOperatorRoots()
  if (typeof r === 'string') problem.value = r
  else text.value = r.join('\n')
}

async function save(roots: string[]): Promise<void> {
  saved.value = false
  problem.value = (await setOperatorRoots(roots)) ?? ''
  if (problem.value === stepUpRequired) {
    startStepUp('operator-roots', 'settings', roots)
    return
  }
  saved.value = !problem.value
  if (saved.value) await load()
}

async function onSave(): Promise<void> {
  const confirmed = await confirm({
    title: t('managedFiles.roots.confirmTitle'), message: t('managedFiles.roots.confirm', { count: lines().length }),
    confirmLabel: t('common.save'),
  })
  if (confirmed) await save(lines())
}

onMounted(async () => {
  await load()
  const pending = resumeStepUp<string[]>('operator-roots', 'settings')
  if (!pending) return
  await router.replace(withoutStepUpParam())
  if (pending.failed) problem.value = 'step_up_failed'
  else await save(pending.payload)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('managedFiles.roots.title') }}</h1>
    <p class="summary">
      {{ t('managedFiles.roots.intro') }}
    </p>
    <v-alert
      type="warning"
      variant="tonal"
      class="conflict"
      data-testid="roots-warning"
    >
      {{ t('managedFiles.roots.warning') }}
    </v-alert>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <v-alert
      v-if="saved"
      type="success"
      variant="tonal"
      class="conflict"
      data-testid="roots-saved"
    >
      {{ t('managedFiles.roots.saved') }}
    </v-alert>
    <form
      class="form"
      novalidate
      @submit.prevent="run(onSave)"
    >
      <v-textarea
        id="operator-roots"
        v-model="text"
        :label="t('managedFiles.roots.label')"
        :hint="t('managedFiles.roots.hint')"
        persistent-hint
        rows="6"
        :readonly="!session.canDelete"
        data-testid="operator-roots"
      />
      <div
        v-if="session.canDelete"
        class="form-actions"
      >
        <v-btn
          type="submit"
          :loading="pending"
          :disabled="pending"
          color="primary"
          data-testid="save-roots"
        >
          {{ t('common.save') }}
        </v-btn>
      </div>
    </form>
  </section>
</template>
