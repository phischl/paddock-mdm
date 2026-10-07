<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { DMSSettings, DMSSettingsUpdate } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { dmsMaxPeriod, dmsMinPeriod, dmsWarnBelow, getDMS, parseWarnDays, saveDMS } from '../lib/revocations'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The organization's dead man's switch (plan M4c decisions 15 and 18): on, the period and the warning lead times.
 * Turning it on, or changing it while on, needs a step-up and a confirmation that names the consequence.
 */
const { t, locale } = useI18n()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()

const loaded = ref(false)
const enabled = ref(false)
const period = ref('30')
const warnDays = ref('3, 1')
const updatedAt = ref('')
const problem = ref('')
const saved = ref(false)

const periodNumber = computed(() => Number(period.value))
const periodError = computed(() =>
  Number.isInteger(periodNumber.value) && periodNumber.value >= dmsMinPeriod && periodNumber.value <= dmsMaxPeriod
    ? ''
    : t('dms.periodInvalid', { min: dmsMinPeriod, max: dmsMaxPeriod }),
)
const warnError = computed(() => {
  const days = parseWarnDays(warnDays.value)
  return days && days.length <= 5 && days.every((d) => d >= 1 && d < periodNumber.value) ? '' : t('dms.warnDaysInvalid')
})
const shortPeriod = computed(() => !periodError.value && periodNumber.value < dmsWarnBelow)

function apply(s: DMSSettings): void {
  enabled.value = s.enabled
  period.value = String(s.period_days)
  warnDays.value = s.warn_days.join(', ')
  updatedAt.value = s.updated_at ?? ''
  loaded.value = true
}

function body(): DMSSettingsUpdate {
  return { enabled: enabled.value, period_days: periodNumber.value, warn_days: parseWarnDays(warnDays.value) ?? [] }
}

async function save(): Promise<void> {
  problem.value = ''
  saved.value = false
  if (periodError.value || warnError.value) return
  await submit(body())
}

/** Confirms a switch that is on, then saves; a step_up_required answer starts the step-up and comes back here. */
async function submit(s: DMSSettingsUpdate): Promise<void> {
  if (s.enabled) {
    const confirmed = await confirm({
      title: t('dms.confirm.title'), message: t('dms.confirm.message', { days: s.period_days }),
      confirmLabel: t('dms.confirm.label'), destructive: true,
    })
    if (!confirmed) return
  }
  const res = await saveDMS(s)
  if (res === stepUpRequired) {
    startStepUp('dms-settings', 'organization', s)
    return
  }
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}

onMounted(async () => {
  const s = await getDMS()
  if (typeof s === 'string') {
    problem.value = s
    return
  }
  apply(s)
  const resumed = resumeStepUp<DMSSettingsUpdate>('dms-settings', 'organization')
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  enabled.value = resumed.payload.enabled
  period.value = String(resumed.payload.period_days)
  warnDays.value = resumed.payload.warn_days.join(', ')
  await submit(resumed.payload)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('dms.title') }}</h1>
    <p
      v-if="updatedAt"
      class="summary"
    >
      {{ t('loginSettings.updatedAt', { at: formatDateTime(updatedAt, locale) }) }}
    </p>
    <v-alert
      v-if="!session.me?.revocation_enabled"
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="revocation-disabled"
    >
      {{ t('revocations.disabled') }}
    </v-alert>
    <v-alert
      type="warning"
      variant="tonal"
      class="conflict"
      data-testid="dms-warning"
    >
      {{ t('dms.warning') }}
    </v-alert>
    <form
      v-if="loaded"
      class="form settings-form"
      novalidate
      @submit.prevent="save"
    >
      <fieldset :disabled="!session.canDelete || !session.me?.revocation_enabled">
        <legend>{{ t('dms.title') }}</legend>
        <v-switch
          id="dms-enabled"
          v-model="enabled"
          :label="t('dms.enabled')"
          color="error"
          inset
          data-testid="dms-enabled"
        />
        <v-text-field
          id="dms-period"
          v-model="period"
          :label="t('dms.period')"
          :hint="t('dms.periodHint')"
          persistent-hint
          type="number"
          :min="dmsMinPeriod"
          :max="dmsMaxPeriod"
          :error-messages="periodError ? [periodError] : []"
          data-testid="dms-period"
        />
        <v-alert
          v-if="shortPeriod"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="dms-short-period"
        >
          {{ t('dms.shortPeriod', { days: dmsWarnBelow }) }}
        </v-alert>
        <v-text-field
          id="dms-warn-days"
          v-model="warnDays"
          :label="t('dms.warnDays')"
          :hint="t('dms.warnDaysHint')"
          persistent-hint
          :error-messages="warnError ? [warnError] : []"
          data-testid="dms-warn-days"
        />
      </fieldset>
      <p
        v-if="problem"
        class="form-error"
        role="alert"
      >
        {{ problemText(problem) }}
      </p>
      <div
        v-if="session.canDelete && session.me?.revocation_enabled"
        class="form-actions"
      >
        <span
          v-if="saved"
          role="status"
        >{{ t('dms.saved') }}</span>
        <v-btn
          type="submit"
          color="primary"
          data-testid="save-dms"
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
  </section>
</template>
