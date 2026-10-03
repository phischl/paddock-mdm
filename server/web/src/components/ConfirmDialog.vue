<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ComponentPublicInstance } from 'vue'

/**
 * Modal confirmation (ADR 0018): title, consequence in one sentence, focus on Cancel, Esc cancels, destructive
 * button in the error colour; high-risk actions require typing a text.
 */
const props = defineProps<{
  modelValue: boolean
  title: string
  message: string
  confirmLabel: string
  destructive?: boolean
  requireTypedText?: string
}>()

const emit = defineEmits<{
  confirm: []
  cancel: []
}>()

const { t } = useI18n()
const id = useId()
const typed = ref('')
const cancelButton = ref<ComponentPublicInstance | null>(null)
const canConfirm = computed(() => !props.requireTypedText || typed.value === props.requireTypedText)

function focusCancel(): void {
  ;(cancelButton.value?.$el as HTMLElement | undefined)?.focus()
}

// Focus on Cancel as soon as the dialog renders and again after its transition, when Vuetify would move focus to
// the dialog container.
watch(
  () => props.modelValue,
  (open) => {
    typed.value = ''
    if (open) void nextTick(focusCancel)
  },
  { immediate: true },
)

function onConfirm(): void {
  if (canConfirm.value) emit('confirm')
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="32rem"
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
        <v-text-field
          v-if="requireTypedText"
          v-model="typed"
          class="confirm-typed"
          :label="t('confirm.typeToConfirm', { text: requireTypedText })"
          autocomplete="off"
          spellcheck="false"
          data-testid="confirm-typed"
          @keydown.enter.prevent="onConfirm"
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
