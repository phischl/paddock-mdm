<script setup lang="ts">
import { computed, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { urgentReasonMax, validUrgent, type UrgentInput } from '../lib/configRollouts'

/**
 * The urgent opt-out of a configuration write (plan M11 decision 37): apply to every device at once instead of
 * staging, with a reason. Shown only while the organization's rollouts are enabled; the portal is the only place for
 * it, because an API token never satisfies the step-up it needs (ADR 0034).
 */
const props = defineProps<{ modelValue: UrgentInput; enabled: boolean; showErrors?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: UrgentInput] }>()
const { t } = useI18n()
const id = useId()
const invalid = computed(() => props.showErrors === true && !validUrgent(props.modelValue))
</script>

<template>
  <div
    v-if="enabled"
    class="urgent-opt-out"
    data-testid="urgent-opt-out"
  >
    <v-checkbox
      :id="id + '-urgent'"
      :model-value="modelValue.urgent"
      :label="t('rollout.urgent.label')"
      :hint="t('rollout.urgent.hint')"
      persistent-hint
      density="comfortable"
      data-testid="urgent-checkbox"
      @update:model-value="(v: boolean | null) => emit('update:modelValue', { ...modelValue, urgent: v === true })"
    />
    <v-textarea
      v-if="modelValue.urgent"
      :id="id + '-reason'"
      :model-value="modelValue.reason"
      :label="t('rollout.urgent.reason')"
      rows="2"
      auto-grow
      :counter="urgentReasonMax"
      :error-messages="invalid ? [t('rollout.urgent.reasonInvalid')] : []"
      data-testid="urgent-reason"
      @update:model-value="(v: string) => emit('update:modelValue', { ...modelValue, reason: v })"
    />
  </div>
</template>
