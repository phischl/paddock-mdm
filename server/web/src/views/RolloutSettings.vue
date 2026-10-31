<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { RolloutSettings, RolloutSettingsUpdate } from '../api/client'
import { allGroups } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import {
  formatWaves, getRolloutSettings, minWaveMinutesProduction, parseWaves, saveRolloutSettings, validateRolloutSettings,
} from '../lib/rolloutSettings'
import { hasErrors } from '../lib/validation'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/**
 * The organization's settings of staged configuration rollouts (plan M11 decisions 23 and 24): whether they are on,
 * the waves, the minimum wave duration, the failure threshold and the canary device group. Only organization
 * administrators change them.
 */
const { t, locale } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const session = useSessionStore()

const form = ref<RolloutSettingsUpdate | null>(null)
const wavesText = ref('')
const canary = ref('')
const groups = ref<{ id: string; name: string }[]>([])
const updatedAt = ref('')
const problem = ref('')
const saved = ref(false)
const touched = ref(false)
const errors = computed(() => (form.value ? validateRolloutSettings(form.value, wavesText.value) : {}))
const canaryItems = computed(() => [{ id: '', name: t('rolloutSettings.canaryNone') }, ...groups.value])

function apply(s: RolloutSettings): void {
  const { updated_at: at, ...rest } = s
  form.value = rest
  canary.value = rest.canary_device_group_id ?? ''
  wavesText.value = formatWaves(s.waves)
  updatedAt.value = at ?? ''
}

function message(key: keyof ReturnType<typeof validateRolloutSettings>): string[] {
  const k = errors.value[key]
  return touched.value && k ? [t(k)] : []
}

async function save(): Promise<void> {
  touched.value = true
  problem.value = ''
  saved.value = false
  if (!form.value || hasErrors(errors.value)) return
  const res = await saveRolloutSettings({
    ...form.value, waves: parseWaves(wavesText.value) ?? [], canary_device_group_id: canary.value || null,
  })
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}

onMounted(async () => {
  const [s, all] = await Promise.all([getRolloutSettings(), allGroups()])
  groups.value = all
  if (typeof s === 'string') problem.value = s
  else apply(s)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('rolloutSettings.title') }}</h1>
    <p class="summary">
      {{ t('rolloutSettings.intro') }}
    </p>
    <p
      v-if="updatedAt"
      class="summary"
    >
      {{ t('loginSettings.updatedAt', { at: formatDateTime(updatedAt, locale) }) }}
    </p>
    <form
      v-if="form"
      class="form settings-form"
      novalidate
      @submit.prevent="run(save)"
    >
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('rolloutSettings.general') }}</legend>
        <v-switch
          id="rollout-enabled"
          v-model="form.enabled"
          :label="t('rolloutSettings.enabled')"
          color="primary"
          inset
          data-testid="rollout-enabled"
        />
        <v-text-field
          id="rollout-waves"
          v-model="wavesText"
          :label="t('rolloutSettings.waves')"
          :hint="t('rolloutSettings.wavesHint')"
          persistent-hint
          :error-messages="message('waves')"
          data-testid="rollout-waves"
        />
        <v-text-field
          id="rollout-min-wave"
          v-model.number="form.min_wave_minutes"
          type="number"
          :label="t('rolloutSettings.minWaveMinutes')"
          :suffix="t('common.units.minutes')"
          :hint="t('rolloutSettings.minWaveMinutesHint', { min: minWaveMinutesProduction })"
          persistent-hint
          :error-messages="message('min_wave_minutes')"
          data-testid="rollout-min-wave"
        />
      </fieldset>
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('rolloutSettings.thresholds') }}</legend>
        <v-text-field
          id="rollout-threshold-percent"
          v-model.number="form.failure_threshold_percent"
          type="number"
          :label="t('rolloutSettings.thresholdPercent')"
          suffix="%"
          :hint="t('rolloutSettings.thresholdPercentHint')"
          persistent-hint
          :error-messages="message('failure_threshold_percent')"
          data-testid="rollout-threshold-percent"
        />
        <v-text-field
          id="rollout-threshold-min"
          v-model.number="form.failure_threshold_min"
          type="number"
          :label="t('rolloutSettings.thresholdMin')"
          :hint="t('rolloutSettings.thresholdMinHint')"
          persistent-hint
          :error-messages="message('failure_threshold_min')"
          data-testid="rollout-threshold-min"
        />
      </fieldset>
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('rolloutSettings.canary') }}</legend>
        <v-select
          id="rollout-canary"
          v-model="canary"
          :items="canaryItems"
          item-title="name"
          item-value="id"
          :label="t('rolloutSettings.canaryGroup')"
          :hint="t('rolloutSettings.canaryHint')"
          persistent-hint
          data-testid="rollout-canary"
        />
      </fieldset>
      <p
        v-if="!session.canDelete"
        class="pd-type-caption pd-muted"
        data-testid="rollout-read-only"
      >
        {{ t('rolloutSettings.readOnly') }}
      </p>
      <p
        v-if="problem"
        class="form-error"
        role="alert"
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
          :disabled="pending"
          color="primary"
          data-testid="save-rollout-settings"
        >
          {{ t('common.save') }}
        </v-btn>
      </div>
    </form>
    <p
      v-else-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <v-snackbar
      v-model="saved"
      color="success"
      data-testid="rollout-saved"
    >
      {{ t('rolloutSettings.saved') }}
    </v-snackbar>
  </section>
</template>
