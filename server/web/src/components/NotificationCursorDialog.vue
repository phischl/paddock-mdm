<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

/**
 * Enabling a disabled destination asks where delivery resumes (plan M9 decision 16): continue delivers the events
 * since it was disabled, skip starts at the newest one.
 */
const props = defineProps<{ modelValue: boolean; name: string; backlog: number | null }>()
const emit = defineEmits<{ choose: [cursor: 'continue' | 'skip']; cancel: [] }>()

const { t } = useI18n()
const choice = ref<'continue' | 'skip'>('continue')
watch(() => props.modelValue, () => { choice.value = 'continue' })
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="32rem"
    :aria-label="t('notifications.cursor.title')"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
  >
    <v-card
      :title="t('notifications.cursor.title')"
      data-testid="notification-cursor-dialog"
      @keydown.esc.stop="emit('cancel')"
    >
      <v-card-text>
        <p>{{ t('notifications.cursor.message', { name }) }}</p>
        <v-radio-group
          v-model="choice"
          hide-details
        >
          <v-radio
            :label="backlog === null ? t('notifications.cursor.continueUnknown') : t('notifications.cursor.continue', { count: backlog })"
            value="continue"
            data-testid="cursor-continue"
          />
          <v-radio
            :label="t('notifications.cursor.skip')"
            value="skip"
            data-testid="cursor-skip"
          />
        </v-radio-group>
        <div class="form-actions">
          <v-btn
            variant="tonal"
            data-testid="cursor-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="primary"
            data-testid="cursor-accept"
            @click="emit('choose', choice)"
          >
            {{ t('notifications.cursor.enable') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
