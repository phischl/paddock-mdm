<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { hasErrors, validateDeviceGroup } from '../lib/validation'
import { useProblemText } from '../lib/problems'
import type { AgentUpdatePolicy, DeviceGroupStaleness, DiskUnlockMode } from '../api/client'
import type { DeviceGroupInput } from '../lib/deviceGroupPage'
import { laptopStaleness } from '../lib/deviceGroups'
import { maxCriticalH, maxWarningH, validateStaleness } from '../lib/updates'

const props = withDefaults(
  defineProps<{
    submitLabel: string
    initialName?: string
    initialDescription?: string
    initialStaleness?: DeviceGroupStaleness | null
    initialAgentUpdatePolicy?: AgentUpdatePolicy | null
    initialDiskUnlockMode?: DiskUnlockMode | null
    problem?: string
    idPrefix?: string
    pending?: boolean
  }>(),
  { initialName: '', initialDescription: '', initialStaleness: null, initialAgentUpdatePolicy: null, initialDiskUnlockMode: null, problem: '', idPrefix: 'device-group', pending: false },
)
const emit = defineEmits<{
  submit: [form: DeviceGroupInput]
  cancel: []
}>()

const { t } = useI18n()
const problemText = useProblemText()
const name = ref(props.initialName)
const description = ref(props.initialDescription)
const touched = ref(false)
const override = ref(props.initialStaleness !== null)
const warningH = ref<number>(props.initialStaleness?.warning_h ?? laptopStaleness.warning_h)
const criticalH = ref<number>(props.initialStaleness?.critical_h ?? laptopStaleness.critical_h)
const agentUpdatePolicy = ref<AgentUpdatePolicy | null>(props.initialAgentUpdatePolicy)
const policyItems = computed(() => [
  { value: null, title: t('deviceGroups.inherit') },
  { value: 'automatic', title: t('updateSettings.agentUpdates.automatic') },
  { value: 'manual', title: t('updateSettings.agentUpdates.manual') },
])
const diskUnlockMode = ref<DiskUnlockMode | null>(props.initialDiskUnlockMode)
const unlockItems = computed(() => [
  { value: null, title: t('deviceGroups.inherit') },
  { value: 'tpm_pin', title: t('devices.disk.unlockModes.tpm_pin') },
  { value: 'tpm_only', title: t('devices.disk.unlockModes.tpm_only') },
])

function laptopPreset(): void {
  override.value = true
  warningH.value = laptopStaleness.warning_h
  criticalH.value = laptopStaleness.critical_h
}
const errors = computed(() => validateDeviceGroup(name.value, description.value))
const nameError = computed(() => (touched.value && errors.value.name ? t(errors.value.name) : ''))
const descriptionError = computed(() => (touched.value && errors.value.description ? t(errors.value.description) : ''))
const stalenessErrors = computed(() => (override.value ? validateStaleness(warningH.value, criticalH.value) : {}))
const warningError = computed(() => (touched.value && stalenessErrors.value.warning_h ? t(stalenessErrors.value.warning_h) : ''))
const criticalError = computed(() => (touched.value && stalenessErrors.value.critical_h ? t(stalenessErrors.value.critical_h) : ''))

function submit(): void {
  touched.value = true
  if (hasErrors(errors.value) || hasErrors(stalenessErrors.value)) return
  emit('submit', {
    name: name.value, description: description.value,
    staleness: override.value ? { warning_h: Number(warningH.value), critical_h: Number(criticalH.value) } : null,
    agent_update_policy: agentUpdatePolicy.value,
    disk_unlock_mode: diskUnlockMode.value,
  })
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-text-field
      :id="idPrefix + '-name'"
      v-model="name"
      :label="t('common.name')"
      name="name"
      autocomplete="off"
      :error-messages="nameError ? [nameError] : []"
      :aria-invalid="!!nameError"
    />
    <v-textarea
      :id="idPrefix + '-description'"
      v-model="description"
      :label="t('common.description')"
      name="description"
      rows="3"
      :error-messages="descriptionError ? [descriptionError] : []"
      :aria-invalid="!!descriptionError"
    />
    <fieldset
      class="pd-group-staleness"
      data-testid="group-staleness"
    >
      <legend>{{ t('deviceGroups.staleness.title') }}</legend>
      <v-switch
        :id="idPrefix + '-staleness-override'"
        v-model="override"
        :label="t('deviceGroups.staleness.override')"
        color="primary"
        hide-details
        data-testid="group-staleness-override"
      />
      <v-text-field
        :id="idPrefix + '-staleness-warning'"
        v-model.number="warningH"
        type="number"
        :disabled="!override"
        :label="t('deviceGroups.staleness.warning')"
        :suffix="t('common.units.hours')"
        :hint="t('deviceGroups.staleness.warningHint', { min: 1, max: maxWarningH })"
        persistent-hint
        class="mb-2"
        :error-messages="warningError ? [warningError] : []"
        :aria-invalid="!!warningError"
        data-testid="group-staleness-warning"
      />
      <v-text-field
        :id="idPrefix + '-staleness-critical'"
        v-model.number="criticalH"
        type="number"
        :disabled="!override"
        :label="t('deviceGroups.staleness.critical')"
        :suffix="t('common.units.hours')"
        :hint="t('deviceGroups.staleness.criticalHint', { max: maxCriticalH })"
        persistent-hint
        :error-messages="criticalError ? [criticalError] : []"
        :aria-invalid="!!criticalError"
        data-testid="group-staleness-critical"
      />
      <v-btn
        type="button"
        variant="tonal"
        size="small"
        data-testid="group-staleness-laptop"
        @click="laptopPreset"
      >
        {{ t('deviceGroups.staleness.laptopPreset') }}
      </v-btn>
      <p class="pd-type-caption pd-muted">
        {{ t('deviceGroups.staleness.hint') }}
      </p>
    </fieldset>
    <v-select
      :id="idPrefix + '-agent-updates'"
      v-model="agentUpdatePolicy"
      :items="policyItems"
      :label="t('deviceGroups.agentUpdates.label')"
      data-testid="group-agent-updates"
    />
    <v-select
      :id="idPrefix + '-unlock-mode'"
      v-model="diskUnlockMode"
      :items="unlockItems"
      :label="t('deviceGroups.unlockMode.label')"
      data-testid="group-unlock-mode"
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
        :loading="pending"
        :disabled="pending"
        color="primary"
      >
        {{ submitLabel }}
      </v-btn>
    </div>
  </form>
</template>
