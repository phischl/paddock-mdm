<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ComponentPublicInstance } from 'vue'
import { reducedMotion } from '../lib/pageContext'
import { uninstallModes, type UninstallAnswer, type UninstallMode } from '../lib/uninstall'

/**
 * The confirmation of Remove Paddock (plan M8d decision 42), laid out like ConfirmDialog: the mode with its
 * explanation, the reset options (clearing the TPM is disabled while a disk unlocks with it), the reason and the
 * typed hostname. Focus starts on Cancel; Esc cancels; Enter in the fields never submits.
 */
const props = defineProps<{ modelValue: boolean; hostname: string; diskTpm: boolean }>()
const emit = defineEmits<{ confirm: [answer: UninstallAnswer]; cancel: [] }>()

const { t } = useI18n()
const id = useId()
const mode = ref<UninstallMode>('leave')
const clearTpm = ref(false)
const keepLocalAdmin = ref(false)
const reason = ref('')
const typed = ref('')
const cancelButton = ref<ComponentPublicInstance | null>(null)
const card = ref<ComponentPublicInstance | null>(null)

const canConfirm = computed(() => typed.value === props.hostname && reason.value.trim().length >= 2)

function focusCancel(): void {
  ;(cancelButton.value?.$el as HTMLElement | undefined)?.focus()
}

function focusCancelAfterEnter(): void {
  if ((card.value?.$el as HTMLElement | undefined)?.contains(document.activeElement)) return
  focusCancel()
}

// Every opening starts empty: a typed hostname must never confirm a different request.
watch(
  () => [props.modelValue, props.hostname] as const,
  ([open]) => {
    mode.value = 'leave'
    clearTpm.value = false
    keepLocalAdmin.value = false
    reason.value = ''
    typed.value = ''
    if (open) void nextTick(focusCancel)
  },
  { immediate: true },
)

function onConfirm(): void {
  if (!canConfirm.value) return
  const reset = mode.value === 'reset'
  emit('confirm', {
    mode: mode.value, clearTpm: reset && clearTpm.value && !props.diskTpm, keepLocalAdmin: reset && keepLocalAdmin.value,
    reason: reason.value.trim(),
  })
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="560"
    :transition="reducedMotion() ? false : 'dialog-transition'"
    :aria-labelledby="id + '-title'"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
    @after-enter="focusCancelAfterEnter"
  >
    <v-card
      ref="card"
      data-testid="uninstall-dialog"
      @keydown.esc.stop="emit('cancel')"
    >
      <v-card-title
        :id="id + '-title'"
        tag="h2"
        class="confirm-title"
      >
        {{ t('devices.uninstall.title', { hostname }) }}
      </v-card-title>
      <v-card-text>
        <v-radio-group
          v-model="mode"
          :aria-labelledby="id + '-title'"
          data-testid="uninstall-mode"
        >
          <v-radio
            v-for="m in uninstallModes"
            :key="m"
            :value="m"
            :label="t('devices.uninstall.' + m + '.label')"
            :data-testid="'uninstall-mode-' + m"
          />
        </v-radio-group>
        <p data-testid="uninstall-explanation">
          {{ t('devices.uninstall.' + mode + '.explanation') }}
        </p>
        <template v-if="mode === 'reset'">
          <v-checkbox
            v-model="clearTpm"
            :label="t('devices.uninstall.clearTpm.label')"
            :disabled="diskTpm"
            :hide-details="diskTpm"
            :aria-describedby="diskTpm ? id + '-clear-tpm-hint' : undefined"
            data-testid="uninstall-clear-tpm"
          />
          <!-- Outside the checkbox: a hint inside the disabled control inherits its opacity and fails the contrast
               minimum, but it carries the reason and has to stay readable. -->
          <p
            v-if="diskTpm"
            :id="id + '-clear-tpm-hint'"
            class="pd-type-caption pd-uninstall-hint"
            data-testid="uninstall-clear-tpm-hint"
          >
            {{ t('devices.uninstall.clearTpm.disabledTpmDisk') }}
          </p>
          <v-checkbox
            v-model="keepLocalAdmin"
            :label="t('devices.uninstall.keepLocalAdmin.label')"
            data-testid="uninstall-keep-local-admin"
          />
        </template>
        <v-textarea
          v-model="reason"
          :label="t('devices.revocation.reason')"
          :hint="t('devices.revocation.reasonHint')"
          persistent-hint
          :counter="500"
          :maxlength="500"
          rows="2"
          auto-grow
          autocomplete="off"
          data-testid="uninstall-reason"
          @keydown.enter.stop
        />
        <v-text-field
          v-model="typed"
          class="confirm-typed"
          :label="t('confirm.typeToConfirm', { text: hostname })"
          :hint="t('devices.uninstall.typed')"
          persistent-hint
          autocomplete="off"
          spellcheck="false"
          data-testid="uninstall-typed"
          @keydown.enter.prevent
        />
        <div class="form-actions">
          <v-btn
            ref="cancelButton"
            variant="tonal"
            data-testid="uninstall-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="error"
            variant="flat"
            :disabled="!canConfirm"
            data-testid="uninstall-accept"
            @click="onConfirm"
          >
            {{ t('devices.uninstall.confirmLabel') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
