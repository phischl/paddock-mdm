<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Lecture, PrivilegeClass, RootEquivalence } from '../api/client'
import { commandLines, lectures, previewRootEquivalence, privilegeClasses, type ProfileInput } from '../lib/profiles'
import { useProblemText } from '../lib/problems'

const props = withDefaults(
  defineProps<{ initial?: ProfileInput; submitLabel: string; problem?: string; idPrefix?: string; pending?: boolean }>(),
  { initial: undefined, problem: '', idPrefix: 'profile', pending: false },
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

// Root equivalence before submit (plan M8x decision 41): 300 ms after the last change the server evaluates the class
// and commands with the rules of the save; a failed preview shows nothing, the save still checks.
const preview = ref<RootEquivalence | null>(null)
let previewTimer: ReturnType<typeof setTimeout> | undefined
let previewSeq = 0
watch([cls, commands], () => {
  clearTimeout(previewTimer)
  preview.value = null
  // Every change invalidates a request already in flight, also when no new one starts: its answer would show a root
  // warning for commands that are gone.
  const seq = ++previewSeq
  const lines = commandLines(commands.value)
  if (cls.value !== 'full' && !(cls.value === 'restricted' && lines.length > 0)) return
  previewTimer = setTimeout(async () => {
    const res = await previewRootEquivalence(cls.value, cls.value === 'full' ? [] : lines)
    if (seq === previewSeq) preview.value = res
  }, 300)
}, { immediate: true })
onBeforeUnmount(() => clearTimeout(previewTimer))
const pairs = computed(() => (preview.value?.witnesses ?? []).filter((w) => w.startsWith('pair:')).map((w) => {
  const [writer, command] = w.slice('pair:'.length).split('|')
  return { writer, command }
}))
const previewText = computed(() => {
  const p = preview.value
  if (!p || p.witnesses.length === 0) return ''
  if (cls.value === 'full') return t('profiles.fullPreview')
  return t('profiles.rootEquivalentPreview', { commands: p.root_equivalent_commands.join(', ') })
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
    <v-alert
      v-if="previewText"
      type="warning"
      variant="tonal"
      data-testid="root-equivalent-preview"
    >
      <p>{{ previewText }}</p>
      <p
        v-for="pair in cls === 'full' ? [] : pairs"
        :key="pair.writer + '|' + pair.command"
      >
        {{ t('profiles.rootEquivalentPair', pair) }}
      </p>
    </v-alert>
    <v-switch
      :id="idPrefix + '-password'"
      v-model="requirePassword"
      :label="t('profiles.requirePassword')"
      :hint="t('profiles.requirePasswordHint')"
      persistent-hint
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
        :loading="pending"
        :disabled="pending"
        color="primary"
      >
        {{ submitLabel }}
      </v-btn>
    </div>
  </form>
</template>
