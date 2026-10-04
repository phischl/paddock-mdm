<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { validityDays, type TokenInput } from '../lib/enrollmentTokens'
import { useProblemText } from '../lib/problems'
import { validateDeviceGroup } from '../lib/validation'

const props = withDefaults(defineProps<{ groups: { id: string; name: string }[]; problem?: string }>(), { problem: '' })
const emit = defineEmits<{ submit: [input: TokenInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const name = ref('')
const validDays = ref<number>(7)
const maxUses = ref<string>('10')
const groupID = ref<string | null>(null)
const autoApprove = ref(false)
const touched = ref(false)
const nameError = computed(() => {
  const key = validateDeviceGroup(name.value, '').name
  return touched.value && key ? t(key) : ''
})
const usesError = computed(() => {
  const n = Number(maxUses.value)
  return touched.value && !(Number.isInteger(n) && n >= 1 && n <= 1000) ? t('validation.maxUsesInvalid') : ''
})

function submit(): void {
  touched.value = true
  if (nameError.value || usesError.value) return
  emit('submit', { name: name.value, validDays: validDays.value, maxUses: Number(maxUses.value), groupID: groupID.value, autoApprove: autoApprove.value })
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-text-field
      id="token-name"
      v-model="name"
      :label="t('common.name')"
      autocomplete="off"
      :error-messages="nameError ? [nameError] : []"
    />
    <v-select
      id="token-validity"
      v-model="validDays"
      :label="t('tokens.validity')"
      :items="validityDays.map((d) => ({ value: d, title: t('tokens.days', { count: d }) }))"
    />
    <v-text-field
      id="token-max-uses"
      v-model="maxUses"
      :label="t('tokens.maxUses')"
      type="number"
      min="1"
      max="1000"
      :error-messages="usesError ? [usesError] : []"
    />
    <v-autocomplete
      id="token-group"
      v-model="groupID"
      :label="t('tokens.group')"
      :items="[{ value: null, title: t('tokens.noGroup') }, ...props.groups.map((g) => ({ value: g.id, title: g.name }))]"
    />
    <v-switch
      id="token-auto-approve"
      v-model="autoApprove"
      :label="t('tokens.autoApprove')"
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
        {{ t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>
