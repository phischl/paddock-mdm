<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceDetail } from '../api/client'
import { usePending } from '../composables/usePending'
import { deviceNameRule, nameStateView, setDeviceName } from '../lib/devices'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

/**
 * The managed name of a device (ADR 0041, plan M8h decision 17): the device applies it as its hostname at its next
 * check-in. Saving and clearing need no confirmation (the change is reversible, ADR 0018); auditors see the state only.
 */
const props = defineProps<{ device: DeviceDetail }>()
const emit = defineEmits<{ saved: [device: DeviceDetail] }>()

const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const session = useSessionStore()

const value = ref(props.device.name ?? '')
const serverError = ref('')
const touched = ref(false)
const saved = ref(false)

watch(
  () => props.device.name,
  (name) => {
    value.value = name ?? ''
  },
)
watch(value, () => {
  serverError.value = ''
})

const state = computed(() => nameStateView(props.device))
const changed = computed(() => value.value !== '' && value.value !== (props.device.name ?? ''))
const rule = computed(() => deviceNameRule(value.value))
// Checked from the first blur or save on, so a half-typed name such as "lap-" is not flagged while typing.
const error = computed(() => (touched.value && rule.value ? t('devices.name.invalid.' + rule.value) : serverError.value))

async function submit(name: string | null): Promise<void> {
  serverError.value = ''
  saved.value = false
  if (name !== null) {
    touched.value = true
    if (rule.value) return
  }
  const res = await setDeviceName(props.device.id, name)
  if ('problem' in res) {
    serverError.value = res.problem === 'conflict'
      ? t('devices.name.conflict')
      : res.problem === 'invalid_request' ? t('devices.name.invalid.server') : problemText(res.problem)
    return
  }
  saved.value = true
  emit('saved', res)
}
</script>

<template>
  <section
    class="pd-panel"
    aria-labelledby="device-name-title"
    data-testid="device-name-panel"
  >
    <header class="pd-panel-header">
      <h2
        id="device-name-title"
        class="pd-type-section"
      >
        {{ t('devices.name.title') }}
      </h2>
    </header>
    <form
      v-if="session.canWrite"
      class="form pd-panel-body"
      novalidate
      @submit.prevent="run(() => submit(value))"
    >
      <v-text-field
        v-model="value"
        :label="t('devices.name.label')"
        :hint="t('devices.name.hint')"
        :error-messages="error"
        :aria-invalid="error ? 'true' : undefined"
        persistent-hint
        autocapitalize="off"
        spellcheck="false"
        maxlength="63"
        data-testid="device-name"
        @blur="touched = true"
      />
      <p
        class="pd-muted"
        data-testid="device-name-state"
      >
        {{ t(state.key, state.values) }}
      </p>
      <div class="form-actions">
        <span
          v-if="saved"
          role="status"
        >{{ t('devices.name.saved') }}</span>
        <v-btn
          v-if="device.name"
          variant="text"
          :disabled="pending"
          data-testid="clear-device-name"
          @click="run(() => submit(null))"
        >
          {{ t('devices.name.clear') }}
        </v-btn>
        <v-btn
          type="submit"
          color="primary"
          :loading="pending"
          :disabled="pending || !changed"
          data-testid="save-device-name"
        >
          {{ t('devices.name.save') }}
        </v-btn>
      </div>
    </form>
    <p
      v-else
      class="pd-panel-body pd-muted"
      data-testid="device-name-state"
    >
      {{ t(state.key, state.values) }}
    </p>
  </section>
</template>
