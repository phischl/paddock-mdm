<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import ConfirmDialog from './ConfirmDialog.vue'
import UrgentOptOut from './UrgentOptOut.vue'
import { noUrgent, validUrgent, type UrgentInput } from '../lib/configRollouts'

/** Confirms the deletion of a managed definition; with rollouts enabled it carries the urgent opt-out (plan M11 decision 37). */
defineProps<{ title: string; message: string; rolloutsEnabled: boolean }>()
const emit = defineEmits<{ confirm: [urgent: UrgentInput]; cancel: [] }>()
const { t } = useI18n()
const urgent = ref(noUrgent())
const touched = ref(false)

function confirm(): void {
  touched.value = true
  if (!validUrgent(urgent.value)) return
  emit('confirm', urgent.value)
}
</script>

<template>
  <ConfirmDialog
    :model-value="true"
    :title="title"
    :message="message"
    :confirm-label="t('common.delete')"
    destructive
    @confirm="confirm"
    @cancel="emit('cancel')"
  >
    <UrgentOptOut
      v-model="urgent"
      :enabled="rolloutsEnabled"
      :show-errors="touched"
    />
  </ConfirmDialog>
</template>
