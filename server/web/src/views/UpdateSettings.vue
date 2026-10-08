<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { UpdateSettings, UpdateSettingsUpdate } from '../api/client'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { getUpdateSettings, saveUpdateSettings, validateSettings } from '../lib/updates'
import { hasErrors } from '../lib/validation'
import { useSessionStore } from '../stores/session'

/**
 * The organization's update settings (plan M5b decisions 1 and 9): when devices install security updates, when they
 * run regular updates, and after how many hours of silence a device is stale.
 */
const { t, locale } = useI18n()
const problemText = useProblemText()
const session = useSessionStore()

const form = ref<UpdateSettingsUpdate | null>(null)
const updatedAt = ref('')
const problem = ref('')
const saved = ref(false)
const touched = ref(false)
const errors = computed(() => (form.value ? validateSettings(form.value) : {}))

function apply(s: UpdateSettings): void {
  const { updated_at: at, ...rest } = s
  form.value = rest
  updatedAt.value = at ?? ''
}

function message(key: keyof ReturnType<typeof validateSettings>): string[] {
  const k = errors.value[key]
  return touched.value && k ? [t(k)] : []
}

async function save(): Promise<void> {
  touched.value = true
  problem.value = ''
  saved.value = false
  if (!form.value || hasErrors(errors.value)) return
  const res = await saveUpdateSettings(form.value)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}

onMounted(async () => {
  const s = await getUpdateSettings()
  if (typeof s === 'string') problem.value = s
  else apply(s)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('updates.settings.title') }}</h1>
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
      @submit.prevent="save"
    >
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('updates.settings.security') }}</legend>
        <v-text-field
          id="security-daily-at"
          v-model="form.security_daily_at"
          :label="t('updates.settings.securityDailyAt')"
          :hint="t('updates.settings.securityDailyAtHint')"
          persistent-hint
          :error-messages="message('security_daily_at')"
          data-testid="security-daily-at"
        />
      </fieldset>
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('updates.settings.regular') }}</legend>
        <v-switch
          id="regular-enabled"
          v-model="form.regular_updates_enabled"
          :label="t('updates.settings.regularEnabled')"
          color="primary"
          inset
          data-testid="regular-enabled"
        />
        <v-text-field
          id="regular-schedule"
          v-model="form.regular_schedule"
          :label="t('updates.settings.regularSchedule')"
          :hint="t('updates.settings.regularScheduleHint')"
          persistent-hint
          :error-messages="message('regular_schedule')"
          data-testid="regular-schedule"
        />
        <v-text-field
          id="max-random-delay"
          v-model.number="form.max_random_delay_min"
          type="number"
          :label="t('updates.settings.maxRandomDelay')"
          :hint="t('updates.settings.maxRandomDelayHint')"
          persistent-hint
          :error-messages="message('max_random_delay_min')"
          data-testid="max-random-delay"
        />
      </fieldset>
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('updates.settings.staleness') }}</legend>
        <v-text-field
          id="staleness-warning"
          v-model.number="form.staleness_warning_h"
          type="number"
          :label="t('updates.settings.stalenessWarning')"
          :error-messages="message('staleness_warning_h')"
          data-testid="staleness-warning"
        />
        <v-text-field
          id="staleness-critical"
          v-model.number="form.staleness_critical_h"
          type="number"
          :label="t('updates.settings.stalenessCritical')"
          :hint="t('updates.settings.stalenessCriticalHint')"
          persistent-hint
          :error-messages="message('staleness_critical_h')"
          data-testid="staleness-critical"
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
        v-if="session.canDelete"
        class="form-actions"
      >
        <span
          v-if="saved"
          role="status"
        >{{ t('updates.settings.saved') }}</span>
        <v-btn
          type="submit"
          color="primary"
          data-testid="save-update-settings"
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
