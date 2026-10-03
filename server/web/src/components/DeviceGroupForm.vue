<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Button from 'primevue/button'
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
    <div class="field">
      <label :for="idPrefix + '-name'">{{ t('common.name') }}</label>
      <InputText
        :id="idPrefix + '-name'"
        v-model="name"
        name="name"
        autocomplete="off"
        :invalid="!!nameError"
        :aria-invalid="!!nameError"
        :aria-describedby="nameError ? idPrefix + '-name-error' : undefined"
      />
      <small
        v-if="nameError"
        :id="idPrefix + '-name-error'"
        class="field-error"
      >{{ nameError }}</small>
    </div>
    <div class="field">
      <label :for="idPrefix + '-description'">{{ t('common.description') }}</label>
      <Textarea
        :id="idPrefix + '-description'"
        v-model="description"
        name="description"
        rows="3"
        :invalid="!!descriptionError"
        :aria-invalid="!!descriptionError"
        :aria-describedby="descriptionError ? idPrefix + '-description-error' : undefined"
      />
      <small
        v-if="descriptionError"
        :id="idPrefix + '-description-error'"
        class="field-error"
      >{{ descriptionError }}</small>
    </div>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <div class="form-actions">
      <Button
        type="button"
        severity="secondary"
        :label="t('common.cancel')"
        @click="emit('cancel')"
      />
      <Button
        type="submit"
        :label="submitLabel"
      />
    </div>
  </form>
</template>
