<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ComponentPublicInstance } from 'vue'
import type { ConfirmReason } from '../composables/useConfirm'
import { reducedMotion } from '../lib/pageContext'

/**
 * Modal confirmation (ADR 0018, plan M7c decision 23): title, consequence in one sentence, an optional reason
 * field, focus on Cancel, Esc cancels, destructive button in the danger colour; high-risk actions require typing a
 * text. Enter in the fields never submits.
 */
const props = defineProps<{
  modelValue: boolean
  title: string
  message: string
  confirmLabel: string
  destructive?: boolean
  requireTypedText?: string
  reason?: ConfirmReason
}>()

const emit = defineEmits<{
  confirm: [answer: { reason: string }]
  cancel: []
}>()

const { t } = useI18n()
const id = useId()
const typed = ref('')
const reasonText = ref('')
const cancelButton = ref<ComponentPublicInstance | null>(null)
const canConfirm = computed(
  () =>
    (!props.requireTypedText || typed.value === props.requireTypedText) &&
    (!props.reason?.required || reasonText.value.trim() !== ''),
)

function focusCancel(): void {
  ;(cancelButton.value?.$el as HTMLElement | undefined)?.focus()
}

// Focus on Cancel as soon as the dialog renders and again after its transition, when Vuetify would move focus to
// the dialog container.
watch(
  () => props.modelValue,
  (open) => {
    typed.value = ''
    reasonText.value = ''
    if (open) void nextTick(focusCancel)
  },
  { immediate: true },
)

function onConfirm(): void {
  if (canConfirm.value) emit('confirm', { reason: reasonText.value.trim() })
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="480"
    :transition="reducedMotion() ? false : 'dialog-transition'"
    :aria-labelledby="id + '-title'"
    :aria-describedby="id + '-message'"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
    @after-enter="focusCancel"
  >
    <v-card
      data-testid="confirm-dialog"
      @keydown.esc.stop="emit('cancel')"
    >
      <v-card-title
        :id="id + '-title'"
        tag="h2"
        class="confirm-title"
      >
        {{ title }}
      </v-card-title>
      <v-card-text>
        <p :id="id + '-message'">
          {{ message }}
        </p>
        <v-textarea
          v-if="reason"
          v-model="reasonText"
          :label="reason.label"
          :hint="reason.hint"
          :persistent-hint="!!reason.hint"
          :counter="reason.maxLength"
          :maxlength="reason.maxLength"
          rows="2"
          auto-grow
          autocomplete="off"
          data-testid="confirm-reason"
          @keydown.enter.stop
        />
        <v-text-field
          v-if="requireTypedText"
          v-model="typed"
          class="confirm-typed"
          :label="t('confirm.typeToConfirm', { text: requireTypedText })"
          autocomplete="off"
          spellcheck="false"
          data-testid="confirm-typed"
          @keydown.enter.prevent
        />
        <div class="form-actions">
          <v-btn
            ref="cancelButton"
            variant="tonal"
            data-testid="confirm-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            :color="destructive ? 'error' : 'primary'"
            variant="flat"
            :disabled="!canConfirm"
            data-testid="confirm-accept"
            @click="onConfirm"
          >
            {{ confirmLabel }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
