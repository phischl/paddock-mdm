<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ManagedFile } from '../api/client'
import { validateFile, type FileInput } from '../lib/managedConfig'
import { useProblemText } from '../lib/problems'
import { hasErrors } from '../lib/validation'

const props = withDefaults(
  defineProps<{ groups: { id: string; name: string }[]; initial?: ManagedFile | null; problem?: string }>(),
  { initial: null, problem: '' },
)
const emit = defineEmits<{ submit: [input: FileInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const form = ref<FileInput>({
  groupID: props.initial?.device_group_id ?? null,
  path: props.initial?.path ?? '',
  mode: props.initial?.mode ?? '0644',
  owner: props.initial?.owner ?? 'root',
  group: props.initial?.group ?? 'root',
  content: props.initial?.content ?? '',
})
const touched = ref(false)
const errors = computed(() => validateFile(form.value))
function message(key: string | undefined): string[] {
  return touched.value && key ? [t(key)] : []
}

function submit(): void {
  touched.value = true
  if (hasErrors(errors.value)) return
  emit('submit', { ...form.value })
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-autocomplete
      id="file-scope"
      v-model="form.groupID"
      data-testid="file-scope"
      :label="t('managed.scope')"
      :items="[{ value: null, title: t('managed.allDevices') }, ...props.groups.map((g) => ({ value: g.id, title: g.name }))]"
      :disabled="initial !== null"
    />
    <v-text-field
      id="file-path"
      v-model="form.path"
      :label="t('managed.files.path')"
      :hint="t('managed.files.pathHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      :error-messages="message(errors.path)"
    />
    <div class="form-row">
      <v-text-field
        id="file-mode"
        v-model="form.mode"
        :label="t('managed.files.mode')"
        :error-messages="message(errors.mode)"
      />
      <v-text-field
        id="file-owner"
        v-model="form.owner"
        :label="t('managed.files.owner')"
        :error-messages="message(errors.owner)"
      />
      <v-text-field
        id="file-group"
        v-model="form.group"
        :label="t('managed.files.group')"
      />
    </div>
    <v-textarea
      id="file-content"
      v-model="form.content"
      :label="t('managed.files.content')"
      rows="8"
      spellcheck="false"
      class="config-text"
      :error-messages="message(errors.content)"
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
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>
