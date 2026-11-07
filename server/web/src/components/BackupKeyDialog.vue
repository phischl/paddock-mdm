<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { answerOf, challengeLength, keyFileText } from '../lib/backup'

/**
 * The backup key dialog (plan M15 decision 27): step 1 explains, step 2 shows the key once with copy and download,
 * step 3 asks for the characters at six positions. The page owns the key text and drops it when the dialog is gone;
 * nothing here stores it. From step 2 on the dialog cannot be closed except by discarding the key.
 */
export interface KeyDialogKey {
  id: string
  /** Null for a key that waits for its confirmation but was shown before (a reload, an imported key). */
  text: string | null
  fingerprint: string
  positions: number[]
  downloadName: string
}

const props = defineProps<{
  step: 1 | 2 | 3
  keyInfo: KeyDialogKey | null
  /** The attempts left after a mismatch; null before the first one. */
  attemptsLeft: number | null
  /** A problem text of the last action. */
  problem: string
  pending: boolean
}>()
const emit = defineEmits<{ generate: []; next: []; confirm: [answer: string]; discard: []; cancel: [] }>()

const { t } = useI18n()
const copied = ref(false)
const chars = ref<string[]>(Array.from({ length: challengeLength }, () => ''))
const inputs = ref<HTMLInputElement[]>([])
const complete = computed(() => chars.value.every((c) => c.length === 1))
const title = computed(() => t('backup.key.dialog.title' + props.step))

// A wrong answer starts the next attempt from empty fields.
watch(() => props.attemptsLeft, () => { chars.value = chars.value.map(() => '') })
watch(() => props.step, (s) => { if (s === 3) void nextTick(() => inputs.value[0]?.focus()) })

async function copy(): Promise<void> {
  if (!props.keyInfo?.text) return
  await navigator.clipboard.writeText(props.keyInfo.text)
  copied.value = true
}

function download(): void {
  const k = props.keyInfo
  if (!k?.text) return
  const url = URL.createObjectURL(new Blob([keyFileText(k.text, k.fingerprint, t('backup.key.fileSentence'))], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = k.downloadName
  a.click()
  URL.revokeObjectURL(url)
}

function onInput(i: number, event: Event): void {
  const value = (event.target as HTMLInputElement).value
  chars.value[i] = value.slice(-1)
  ;(event.target as HTMLInputElement).value = chars.value[i]
  if (chars.value[i] !== '' && i < challengeLength - 1) inputs.value[i + 1]?.focus()
}

function submit(): void {
  if (complete.value) emit('confirm', answerOf(chars.value))
}
</script>

<template>
  <v-dialog
    model-value
    max-width="40rem"
    persistent
    :aria-label="title"
    @keydown.esc.stop="step === 1 && emit('cancel')"
  >
    <v-card
      :title="title"
      data-testid="backup-key-dialog"
    >
      <v-card-text>
        <template v-if="step === 1">
          <p data-testid="backup-key-explain">
            {{ t('backup.key.explain') }}
          </p>
        </template>
        <template v-else-if="step === 2 && keyInfo?.text">
          <v-alert
            type="warning"
            variant="tonal"
          >
            {{ t('backup.key.shownOnce') }}
          </v-alert>
          <v-text-field
            :model-value="keyInfo.text"
            :label="t('backup.key.keyText')"
            readonly
            class="config-text mono"
            data-testid="backup-key-text"
          />
          <p class="pd-muted">
            {{ t('backup.key.fingerprint', { fingerprint: keyInfo.fingerprint }) }}
          </p>
          <div class="form-actions">
            <span
              v-if="copied"
              role="status"
            >{{ t('tokens.copied') }}</span>
            <v-btn
              variant="tonal"
              data-testid="backup-key-copy"
              @click="copy"
            >
              {{ t('tokens.copy') }}
            </v-btn>
            <v-btn
              variant="tonal"
              data-testid="backup-key-download"
              @click="download"
            >
              {{ t('backup.key.download') }}
            </v-btn>
          </div>
        </template>
        <form
          v-else-if="keyInfo"
          novalidate
          data-testid="backup-key-confirm-form"
          @submit.prevent="submit"
        >
          <p>{{ t('backup.key.confirmText') }}</p>
          <div
            class="form-actions"
            role="group"
            :aria-label="t('backup.key.positionsGroup')"
          >
            <div
              v-for="(position, i) in keyInfo.positions"
              :key="position"
            >
              <label
                :for="'backup-key-char-' + i"
                class="pd-type-caption"
              >{{ t('backup.key.position', { n: position }) }}</label>
              <input
                :id="'backup-key-char-' + i"
                :ref="(el) => { if (el) inputs[i] = el as HTMLInputElement }"
                :value="chars[i]"
                class="mono"
                maxlength="2"
                size="2"
                autocomplete="off"
                spellcheck="false"
                :data-testid="'backup-key-char-' + i"
                @input="onInput(i, $event)"
              >
            </div>
          </div>
          <v-alert
            v-if="attemptsLeft !== null"
            type="error"
            variant="tonal"
            class="conflict"
            role="alert"
            data-testid="backup-key-attempts"
          >
            {{ t('backup.key.attemptsLeft', { count: attemptsLeft }) }}
          </v-alert>
        </form>
        <p
          v-if="problem"
          class="form-error"
          role="alert"
          data-testid="backup-key-problem"
        >
          {{ problem }}
        </p>
      </v-card-text>
      <v-card-actions class="form-actions">
        <template v-if="step === 1">
          <v-btn
            variant="tonal"
            data-testid="backup-key-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="primary"
            :loading="pending"
            :disabled="pending"
            data-testid="backup-key-generate"
            @click="emit('generate')"
          >
            {{ t('backup.key.generate') }}
          </v-btn>
        </template>
        <template v-else>
          <v-btn
            color="error"
            variant="tonal"
            :disabled="pending"
            data-testid="backup-key-discard"
            @click="emit('discard')"
          >
            {{ t('backup.key.discard') }}
          </v-btn>
          <v-btn
            v-if="step === 2"
            color="primary"
            data-testid="backup-key-next"
            @click="emit('next')"
          >
            {{ t('backup.key.stored') }}
          </v-btn>
          <v-btn
            v-else
            color="primary"
            :loading="pending"
            :disabled="pending || !complete"
            data-testid="backup-key-confirm"
            @click="submit"
          >
            {{ t('backup.key.confirm') }}
          </v-btn>
        </template>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
