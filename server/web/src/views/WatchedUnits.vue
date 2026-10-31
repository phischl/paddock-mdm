<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { getWatchedUnits, maxWatchedUnits, setWatchedUnits, validateWatchedUnits } from '../lib/watchedUnits'
import { useSessionStore } from '../stores/session'

/**
 * The third-party units of the presence policy (plan M9 decision 38): every device reports when one of them stops.
 * Paddock only watches; changing the list needs a step-up and a confirmation.
 */
const { t, locale } = useI18n()
const { pending, run } = usePending()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()

const units = ref<string[]>([])
const updatedAt = ref('')
const problem = ref('')
const saved = ref(false)
// Set on a 422 unit_not_allowed; it describes the list that was sent, so any change of the list clears it.
const refused = ref(false)

const invalid = computed(() => validateWatchedUnits(units.value))
const invalidText = computed(() => (invalid.value ? t(invalid.value.key, invalid.value.values) : ''))
const errorText = computed(() => invalidText.value || (refused.value ? t('problems.unit_not_allowed') : ''))
watch(units, () => { refused.value = false })

function apply(list: string[], at: string | null): void {
  units.value = list
  updatedAt.value = at ?? ''
}

async function load(): Promise<void> {
  const r = await getWatchedUnits()
  if (typeof r === 'string') problem.value = r
  else apply(r.units, r.updatedAt)
}

async function save(list: string[]): Promise<void> {
  saved.value = false
  refused.value = false
  const r = await setWatchedUnits(list)
  if (r === stepUpRequired) {
    startStepUp('watched-units', 'settings', list)
    return
  }
  if (r === 'unit_not_allowed') {
    refused.value = true
    return
  }
  if (typeof r === 'string') {
    problem.value = r
    return
  }
  problem.value = ''
  apply(r.units, r.updatedAt)
  saved.value = true
}

async function onSave(): Promise<void> {
  problem.value = ''
  if (invalid.value) return
  const confirmed = await confirm({
    title: t('watchedUnits.confirmTitle'), message: t('watchedUnits.confirm', { count: units.value.length }),
    confirmLabel: t('common.save'),
  })
  if (confirmed) await save(units.value)
}

onMounted(async () => {
  await load()
  const resumed = resumeStepUp<string[]>('watched-units', 'settings')
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) problem.value = 'step_up_failed'
  else {
    units.value = resumed.payload
    await save(resumed.payload)
  }
})
</script>

<template>
  <section class="page">
    <h1>{{ t('watchedUnits.title') }}</h1>
    <p class="summary">
      {{ t('watchedUnits.intro') }}
    </p>
    <p
      v-if="updatedAt"
      class="summary"
    >
      {{ t('watchedUnits.updatedAt', { at: formatDateTime(updatedAt, locale) }) }}
    </p>
    <v-alert
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="watched-info"
    >
      {{ t('watchedUnits.info') }}
    </v-alert>
    <v-alert
      v-if="saved"
      type="success"
      variant="tonal"
      class="conflict"
      role="status"
      data-testid="watched-saved"
    >
      {{ t('watchedUnits.saved') }}
    </v-alert>
    <form
      class="form"
      novalidate
      @submit.prevent="run(onSave)"
    >
      <v-combobox
        id="watched-units"
        v-model="units"
        :label="t('watchedUnits.label')"
        :hint="t('watchedUnits.hint', { max: maxWatchedUnits })"
        :placeholder="t('watchedUnits.placeholder')"
        persistent-hint
        multiple
        chips
        closable-chips
        :items="[]"
        :delimiters="[',', ' ']"
        :readonly="!session.canDelete"
        :error-messages="errorText ? [errorText] : []"
        :aria-invalid="errorText ? 'true' : undefined"
        data-testid="watched-units"
      />
      <p
        v-if="problem"
        class="form-error"
        role="alert"
        data-testid="watched-problem"
      >
        {{ problemText(problem) }}
      </p>
      <div
        v-if="session.canDelete"
        class="form-actions"
      >
        <v-btn
          type="submit"
          :loading="pending"
          :disabled="pending || !!invalid"
          color="primary"
          data-testid="save-watched-units"
        >
          {{ t('common.save') }}
        </v-btn>
      </div>
    </form>
  </section>
</template>
