<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ManagedUnit } from '../api/client'
import { validateUnit, type UnitInput } from '../lib/managedConfig'
import { useProblemText } from '../lib/problems'
import { hasErrors } from '../lib/validation'

const props = withDefaults(
  defineProps<{ groups: { id: string; name: string }[]; initial?: ManagedUnit | null; problem?: string }>(),
  { initial: null, problem: '' },
)
const emit = defineEmits<{ submit: [input: UnitInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const form = ref<UnitInput>({
  groupID: props.initial?.device_group_id ?? null,
  unit: props.initial?.unit ?? '',
  enabled: props.initial?.enabled ?? true,
  active: props.initial?.active ?? true,
})
const touched = ref(false)
const errors = computed(() => validateUnit(form.value))

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
      id="unit-scope"
      v-model="form.groupID"
      data-testid="unit-scope"
      :label="t('managed.scope')"
      :items="[{ value: null, title: t('managed.allDevices') }, ...props.groups.map((g) => ({ value: g.id, title: g.name }))]"
      :disabled="initial !== null"
    />
    <v-text-field
      id="unit-name"
      v-model="form.unit"
      :label="t('managed.units.unit')"
      autocomplete="off"
      spellcheck="false"
      :error-messages="touched && errors.unit ? [t(errors.unit)] : []"
    />
    <v-switch
      id="unit-enabled"
      v-model="form.enabled"
      :label="t('managed.units.enabled')"
      color="primary"
      inset
    />
    <v-switch
      id="unit-active"
      v-model="form.active"
      :label="t('managed.units.active')"
      color="primary"
      inset
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
