<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import ConfirmDialog from './ConfirmDialog.vue'
import type { Organization } from '../api/client'
import { graceDays } from '../lib/organizations'

/**
 * Confirms the deletion of an organization (plan M17 decision 2): the slug is typed, the reason is kept in the audit
 * trail and the grace period decides how long the organization stays usable. The server owns the final bounds.
 */
const props = defineProps<{ org: Organization }>()
const emit = defineEmits<{ confirm: [answer: { reason: string; graceDays: number }]; cancel: [] }>()
const { t } = useI18n()
const grace = ref(String(graceDays.default))
const graceValue = computed(() => (/^\d+$/.test(grace.value.trim()) ? Number(grace.value.trim()) : Number.NaN))
const graceValid = computed(() => graceValue.value >= graceDays.min && graceValue.value <= graceDays.max)
const graceError = computed(() => (graceValid.value ? [] : [t('organizations.delete.graceInvalid', { min: graceDays.min, max: graceDays.max })]))

function confirm(answer: { reason: string }): void {
  if (!graceValid.value) return
  emit('confirm', { reason: answer.reason, graceDays: graceValue.value })
}
</script>

<template>
  <ConfirmDialog
    :model-value="true"
    :title="t('organizations.delete.title', { name: props.org.name })"
    :message="t('organizations.delete.message', { name: props.org.name })"
    :confirm-label="t('organizations.delete.confirm')"
    destructive
    :require-typed-text="props.org.slug"
    :reason="{ label: t('organizations.delete.reason'), hint: t('organizations.delete.reasonHint'), required: true, minLength: 2, maxLength: 500 }"
    @confirm="confirm"
    @cancel="emit('cancel')"
  >
    <v-text-field
      v-model="grace"
      type="number"
      inputmode="numeric"
      :min="graceDays.min"
      :max="graceDays.max"
      :label="t('organizations.delete.grace')"
      :hint="t('organizations.delete.graceHint')"
      persistent-hint
      autocomplete="off"
      :error-messages="graceError"
      :aria-invalid="!graceValid"
      data-testid="delete-grace-days"
      @keydown.enter.prevent
    />
  </ConfirmDialog>
</template>
