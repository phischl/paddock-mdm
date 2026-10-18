<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ComponentPublicInstance } from 'vue'
import type { AutoUnsealAcknowledgement } from '../lib/autoUnseal'
import { reducedMotion } from '../lib/pageContext'

/**
 * The disclaimer of the automatic unseal of OpenBao (ADR 0035, plan M8u decision 23) in the conventions of
 * ConfirmDialog: focus on Cancel, Esc cancels, Enter never submits. The confirm button stays disabled until the
 * acknowledgement sentence of the current locale is typed exactly, byte for byte.
 */
const props = defineProps<{
  modelValue: boolean
  /** The current version of the disclaimer, as GET returns it. */
  version: string
  pending?: boolean
}>()

const emit = defineEmits<{
  confirm: [input: AutoUnsealAcknowledgement]
  cancel: []
}>()

const { t } = useI18n()
const id = useId()
const typed = ref('')
const cancelButton = ref<ComponentPublicInstance | null>(null)
const card = ref<ComponentPublicInstance | null>(null)
const sentence = computed(() => t('openbao.disclaimer.sentence'))
const canConfirm = computed(() => typed.value === sentence.value && !props.pending)
const risks = ['risk1', 'risk2', 'risk3', 'risk4'] as const

function focusCancel(): void {
  ;(cancelButton.value?.$el as HTMLElement | undefined)?.focus()
}

/** After the transition focus goes back to Cancel, unless someone is typing inside the dialog already. */
function focusCancelAfterEnter(): void {
  if ((card.value?.$el as HTMLElement | undefined)?.contains(document.activeElement)) return
  focusCancel()
}

// Every opening starts with an empty field: an acknowledgement typed earlier never confirms a later opening.
watch(
  () => props.modelValue,
  (open) => {
    typed.value = ''
    if (open) void nextTick(focusCancel)
  },
  { immediate: true },
)

function onConfirm(): void {
  if (canConfirm.value) emit('confirm', { disclaimer_version: props.version, acknowledgement: typed.value })
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="640"
    scrollable
    :transition="reducedMotion() ? false : 'dialog-transition'"
    :aria-labelledby="id + '-title'"
    :aria-describedby="id + '-intro'"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
    @after-enter="focusCancelAfterEnter"
  >
    <v-card
      ref="card"
      data-testid="auto-unseal-disclaimer"
      @keydown.esc.stop="emit('cancel')"
    >
      <v-card-title
        :id="id + '-title'"
        tag="h2"
        class="disclaimer-title"
      >
        {{ t('openbao.disclaimer.title') }}
      </v-card-title>
      <v-card-text>
        <p :id="id + '-intro'">
          {{ t('openbao.disclaimer.intro') }}
        </p>
        <p class="disclaimer-lead">
          {{ t('openbao.disclaimer.lead') }}
        </p>
        <ol
          class="disclaimer-risks"
          data-testid="auto-unseal-risks"
        >
          <li
            v-for="risk in risks"
            :key="risk"
          >
            {{ t('openbao.disclaimer.' + risk) }}
          </li>
        </ol>
        <p>{{ t('openbao.disclaimer.outro', { version }) }}</p>
        <v-text-field
          v-model="typed"
          :label="t('openbao.disclaimer.typeLabel', { sentence })"
          autocomplete="off"
          spellcheck="false"
          data-testid="auto-unseal-typed"
          @keydown.enter.prevent
        />
        <div class="form-actions">
          <v-btn
            ref="cancelButton"
            variant="tonal"
            data-testid="auto-unseal-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="error"
            variant="flat"
            :disabled="!canConfirm"
            :loading="pending"
            data-testid="auto-unseal-accept"
            @click="onConfirm"
          >
            {{ t('openbao.enable') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.disclaimer-title {
  white-space: normal;
}

.disclaimer-lead {
  margin-top: var(--pd-space-3);
  font-weight: 600;
}

.disclaimer-risks {
  margin: var(--pd-space-2) 0 var(--pd-space-3);
  padding-left: var(--pd-space-5);
}

.disclaimer-risks li + li {
  margin-top: var(--pd-space-2);
}
</style>
