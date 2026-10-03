<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { hasErrors, validateDeviceGroup } from '../lib/validation'
import { useProblemText } from '../lib/problems'
import type { DeviceGroupInput } from '../lib/deviceGroupPage'

const props = withDefaults(
  defineProps<{
    submitLabel: string
    initialName?: string
    initialDescription?: string
    problem?: string
    idPrefix?: string
  }>(),
  { initialName: '', initialDescription: '', problem: '', idPrefix: 'device-group' },
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
const errors = computed(() => validateDeviceGroup(name.value, description.value))
const nameError = computed(() => (touched.value && errors.value.name ? t(errors.value.name) : ''))
const descriptionError = computed(() => (touched.value && errors.value.description ? t(errors.value.description) : ''))

function submit(): void {
  touched.value = true
  if (hasErrors(errors.value)) return
  emit('submit', { name: name.value, description: description.value })
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
      >
        {{ submitLabel }}
      </v-btn>
    </div>
  </form>
</template>
