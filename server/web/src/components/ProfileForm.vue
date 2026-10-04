<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Lecture, PrivilegeClass } from '../api/client'
import { commandLines, lectures, privilegeClasses, type ProfileInput } from '../lib/profiles'
import { useProblemText } from '../lib/problems'

const props = withDefaults(
  defineProps<{ initial?: ProfileInput; submitLabel: string; problem?: string; idPrefix?: string }>(),
  { initial: undefined, problem: '', idPrefix: 'profile' },
)
const emit = defineEmits<{ submit: [input: ProfileInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const name = ref(props.initial?.name ?? '')
const cls = ref<PrivilegeClass>(props.initial?.class ?? 'restricted')
const commands = ref((props.initial?.commands ?? []).join('\n'))
const requirePassword = ref(props.initial?.requirePassword ?? true)
const timeout = ref(String(props.initial?.timestampTimeoutMin ?? 5))
const lecture = ref<Lecture>(props.initial?.lecture ?? 'once')
const touched = ref(false)
const nameError = computed(() => (touched.value && name.value.trim() === '' ? t('validation.nameRequired') : ''))
const commandsError = computed(() =>
  touched.value && cls.value === 'restricted' && commandLines(commands.value).length === 0 ? t('profiles.commandsRequired') : '',
)
const timeoutError = computed(() => {
  const n = Number(timeout.value)
  return touched.value && !(Number.isInteger(n) && n >= 0 && n <= 60) ? t('profiles.timeoutInvalid') : ''
})

function submit(): void {
  touched.value = true
  if (nameError.value || commandsError.value || timeoutError.value) return
  emit('submit', {
    name: name.value, class: cls.value, commands: commandLines(commands.value), requirePassword: requirePassword.value,
    timestampTimeoutMin: Number(timeout.value), lecture: lecture.value,
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
      autocomplete="off"
      :error-messages="nameError ? [nameError] : []"
    />
    <v-select
      :id="idPrefix + '-class'"
      v-model="cls"
      :label="t('profiles.class')"
      :items="privilegeClasses.map((c) => ({ value: c, title: t('profiles.classes.' + c) }))"
      :hint="t('profiles.classHints.' + cls)"
      persistent-hint
    />
    <v-textarea
      v-if="cls === 'restricted'"
      :id="idPrefix + '-commands'"
      v-model="commands"
      :label="t('profiles.commands')"
      :hint="t('profiles.commandsHint')"
      persistent-hint
      rows="4"
      :error-messages="commandsError ? [commandsError] : []"
    />
    <v-switch
      :id="idPrefix + '-password'"
      v-model="requirePassword"
      :label="t('profiles.requirePassword')"
      color="primary"
      inset
    />
    <v-text-field
      :id="idPrefix + '-timeout'"
      v-model="timeout"
      :label="t('profiles.timeout')"
      type="number"
      min="0"
      max="60"
      :error-messages="timeoutError ? [timeoutError] : []"
    />
    <v-select
      :id="idPrefix + '-lecture'"
      v-model="lecture"
      :label="t('profiles.lecture')"
      :items="lectures.map((l) => ({ value: l, title: t('profiles.lectures.' + l) }))"
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
