<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { MaintenanceWindow, MaintenanceWindowInput } from '../api/client'
import { useProblemText } from '../lib/problems'
import {
  isoWeekdays, maxDurationMinutes, minDurationMinutes, timezoneNames, validateWindow, windowForm, windowInput,
} from '../lib/maintenanceWindows'

/**
 * The maintenance window of a device group (plan M13c decision 4): the weekdays, the local start time, the length and
 * the timezone. The group's devices install and remove the software of their policy only inside the union of their
 * groups' windows (Q17).
 */
const props = withDefaults(defineProps<{ initial?: MaintenanceWindow | null; problem?: string; pending?: boolean }>(), {
  initial: null, problem: '', pending: false,
})
const emit = defineEmits<{ submit: [input: MaintenanceWindowInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const start = windowForm(props.initial)
const days = ref<number[]>(start.days)
const startTime = ref(start.start)
const duration = ref(start.duration)
const timezone = ref(start.timezone)
const touched = ref(false)
const zones = timezoneNames()
const form = computed(() => ({ days: days.value, start: startTime.value, duration: duration.value, timezone: timezone.value }))
const errors = computed(() => validateWindow(form.value))

function message(key: string | undefined): string[] {
  return touched.value && key ? [t(key)] : []
}

function submit(): void {
  touched.value = true
  const e = errors.value
  if (e.days || e.start || e.duration || e.timezone) return
  emit('submit', windowInput(form.value))
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <fieldset class="window-days">
      <legend>{{ t('maintenanceWindow.days') }}</legend>
      <v-checkbox
        v-for="d in isoWeekdays"
        :key="d"
        v-model="days"
        :value="d"
        :label="t('maintenanceWindow.weekdays.' + d)"
        density="compact"
        hide-details
        :data-testid="'window-day-' + d"
      />
      <p
        v-if="message(errors.days).length"
        class="form-error"
        role="alert"
      >
        {{ message(errors.days)[0] }}
      </p>
    </fieldset>
    <v-text-field
      id="window-start"
      v-model="startTime"
      type="time"
      :label="t('maintenanceWindow.start')"
      :error-messages="message(errors.start)"
      data-testid="window-start"
    />
    <v-text-field
      id="window-duration"
      v-model="duration"
      type="number"
      :min="minDurationMinutes"
      :max="maxDurationMinutes"
      :label="t('maintenanceWindow.duration')"
      :hint="t('maintenanceWindow.durationHint')"
      persistent-hint
      :suffix="t('maintenanceWindow.minutes')"
      :error-messages="message(errors.duration)"
      data-testid="window-duration"
    />
    <v-autocomplete
      v-if="zones.length"
      id="window-timezone"
      v-model="timezone"
      :label="t('maintenanceWindow.timezone')"
      :items="zones"
      :error-messages="message(errors.timezone)"
      data-testid="window-timezone"
    />
    <v-text-field
      v-else
      id="window-timezone"
      v-model="timezone"
      :label="t('maintenanceWindow.timezone')"
      :hint="t('maintenanceWindow.timezoneHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      :error-messages="message(errors.timezone)"
      data-testid="window-timezone"
    />
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <div class="form-actions">
      <v-btn
        type="button"
        variant="tonal"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </v-btn>
      <v-btn
        type="submit"
        color="primary"
        :loading="pending"
        :disabled="pending"
        data-testid="save-window"
      >
        {{ t('common.save') }}
      </v-btn>
    </div>
  </form>
</template>

<style scoped>
.window-days {
  display: flex;
  flex-wrap: wrap;
  gap: 0 1rem;
  border: 0;
  padding: 0;
  margin: 0 0 1rem;
}

.window-days legend {
  margin-bottom: 0.25rem;
}

.window-days .form-error {
  flex-basis: 100%;
}
</style>
