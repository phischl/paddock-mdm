<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { replayFrom } from '../lib/notifications'

/**
 * Asks from which forward sequence number a destination receives its stored batches again (plan M12 decision 21,
 * §6.7): the number is 1 to the last one sent, and the dialog says that the receiver must deduplicate.
 */
const props = defineProps<{ modelValue: boolean; name: string; last: number }>()
const emit = defineEmits<{ replay: [from: number]; cancel: [] }>()

const { t } = useI18n()
const value = ref('1')
const touched = ref(false)
watch(() => props.modelValue, () => { value.value = '1'; touched.value = false })

const from = computed(() => replayFrom(value.value, props.last))
const error = computed(() => (touched.value && from.value === null ? t('notifications.replay.invalid', { last: props.last }) : ''))

function submit(): void {
  touched.value = true
  if (from.value !== null) emit('replay', from.value)
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="32rem"
    :aria-label="t('notifications.replay.title')"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
  >
    <v-card
      :title="t('notifications.replay.title')"
      data-testid="notification-replay-dialog"
      @keydown.esc.stop="emit('cancel')"
    >
      <v-card-text>
        <v-form @submit.prevent="submit">
          <v-text-field
            v-model="value"
            :label="t('notifications.replay.number')"
            :hint="t('notifications.replay.hint', { last, name })"
            persistent-hint
            inputmode="numeric"
            :error-messages="error"
            data-testid="replay-from"
            @blur="touched = true"
          />
          <p
            class="mt-4"
            data-testid="replay-message"
          >
            {{ t('notifications.replay.message', { from: from ?? value.trim() }) }}
          </p>
          <div class="form-actions">
            <v-btn
              variant="tonal"
              data-testid="replay-cancel"
              @click="emit('cancel')"
            >
              {{ t('common.cancel') }}
            </v-btn>
            <v-btn
              color="primary"
              type="submit"
              data-testid="replay-accept"
            >
              {{ t('notifications.replay.confirm') }}
            </v-btn>
          </div>
        </v-form>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
