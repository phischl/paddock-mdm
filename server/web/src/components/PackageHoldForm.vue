<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PackageHold } from '../api/client'
import { useProblemText } from '../lib/problems'
import { validateHold, type HoldInput } from '../lib/updates'
import { hasErrors } from '../lib/validation'

const props = withDefaults(
  defineProps<{ groups: { id: string; name: string }[]; initial?: PackageHold | null; problem?: string }>(),
  { initial: null, problem: '' },
)
const emit = defineEmits<{ submit: [input: HoldInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const form = ref<HoldInput>({
  groupID: props.initial?.device_group_id ?? null,
  package: props.initial?.package ?? '',
  version: props.initial?.version ?? '',
  reason: props.initial?.reason ?? '',
})
const touched = ref(false)
const errors = computed(() => validateHold(form.value))

function submit(): void {
  touched.value = true
  if (hasErrors(errors.value)) return
  emit('submit', { ...form.value, package: form.value.package.trim(), version: form.value.version.trim() })
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-autocomplete
      id="hold-scope"
      v-model="form.groupID"
      data-testid="hold-scope"
      :label="t('managed.scope')"
      :items="[{ value: null, title: t('managed.allDevices') }, ...props.groups.map((g) => ({ value: g.id, title: g.name }))]"
      :disabled="initial !== null"
    />
    <v-text-field
      id="hold-package"
      v-model="form.package"
      :label="t('updates.holds.package')"
      autocomplete="off"
      spellcheck="false"
      :disabled="initial !== null"
      :error-messages="touched && errors.package ? [t(errors.package)] : []"
      data-testid="hold-package"
    />
    <v-text-field
      id="hold-version"
      v-model="form.version"
      :label="t('updates.holds.version')"
      :hint="t('updates.holds.versionHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      :error-messages="touched && errors.version ? [t(errors.version)] : []"
      data-testid="hold-version"
    />
    <v-textarea
      id="hold-reason"
      v-model="form.reason"
      :label="t('updates.holds.reason')"
      rows="2"
      auto-grow
      counter="500"
      :error-messages="touched && errors.reason ? [t(errors.reason)] : []"
      data-testid="hold-reason"
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
        data-testid="save-hold"
      >
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>
