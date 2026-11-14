<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { saveFile } from '../lib/disk'
import { useProblemText } from '../lib/problems'
import { exportRecoveryKeys, passphraseStrength, validateExport } from '../lib/recoveryExport'
import { resumeStepUp, startStepUp, withoutStepUpParam } from '../lib/stepUp'
import { usePending } from '../composables/usePending'

/**
 * The encrypted recovery export of an organization whose deletion is pending (ADR 0052 amendment b, plan M17
 * amendment b decision 26): the button starts the step-up, the dialog then asks for the recipient (a public key, or a
 * passphrase typed twice with a strength hint) and downloads the encrypted file. The passphrase never leaves the
 * dialog's state and the request; it is cleared when the dialog closes.
 */
const props = defineProps<{
  /** The organization of a platform administrator; null exports the administrator's own organization. */
  organizationId: string | null
  slug: string
}>()

const { t } = useI18n()
const router = useRouter()
const problemText = useProblemText()
const { pending, run } = usePending()

const action = 'recovery-export'
const target = computed(() => props.organizationId ?? 'own')
const open = ref(false)
// A public key is the recommended recipient (plan M17 amendment g point 3).
const recipient = ref<'passphrase' | 'public_key'>('public_key')
const publicKey = ref('')
const passphrase = ref('')
const repeat = ref('')
const touched = ref(false)
const problem = ref('')
const done = ref(false)

const request = computed(() => recipient.value === 'public_key'
  ? { recipient: recipient.value, public_key: publicKey.value }
  : { recipient: recipient.value, passphrase: passphrase.value })
const error = computed(() => validateExport(request.value, repeat.value))
const strength = computed(() => passphraseStrength(passphrase.value))

function clear(): void {
  recipient.value = 'public_key'
  publicKey.value = ''
  passphrase.value = ''
  repeat.value = ''
  touched.value = false
}

function start(): void {
  problem.value = ''
  done.value = false
  startStepUp(action, target.value)
}

onMounted(async () => {
  const resumed = resumeStepUp<null>(action, target.value)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  clear()
  open.value = true
})

async function submit(): Promise<void> {
  touched.value = true
  if (error.value) return
  problem.value = ''
  const res = await exportRecoveryKeys(props.organizationId, request.value)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  saveFile(res)
  done.value = true
  close()
}

function close(): void {
  open.value = false
  clear()
}
</script>

<template>
  <div class="recovery-export">
    <v-btn
      color="primary"
      variant="tonal"
      :data-testid="'recovery-export-' + slug"
      @click="start"
    >
      {{ t('recoveryExport.button') }}
    </v-btn>
    <v-alert
      v-if="problem && !open"
      type="error"
      variant="tonal"
      density="compact"
      role="alert"
      class="mt-2"
    >
      {{ problemText(problem) }}
    </v-alert>
    <v-alert
      v-if="done"
      type="success"
      variant="tonal"
      density="compact"
      class="mt-2"
    >
      {{ t('recoveryExport.done') }}
    </v-alert>

    <v-dialog
      v-model="open"
      max-width="36rem"
      persistent
      :aria-label="t('recoveryExport.title')"
      @after-leave="clear"
    >
      <v-card :title="t('recoveryExport.title')">
        <v-card-text>
          <form
            class="form"
            novalidate
            data-testid="recovery-export-form"
            @submit.prevent="run(submit)"
          >
            <p>{{ t('recoveryExport.intro', { slug }) }}</p>
            <v-alert
              type="warning"
              variant="tonal"
              density="compact"
            >
              {{ t('recoveryExport.lastCopy') }}
            </v-alert>
            <v-radio-group
              v-model="recipient"
              :label="t('recoveryExport.recipient')"
            >
              <v-radio
                value="public_key"
                :label="t('recoveryExport.recipientPublicKey')"
                data-testid="recovery-export-public-key"
              />
              <v-radio
                value="passphrase"
                :label="t('recoveryExport.recipientPassphrase')"
                data-testid="recovery-export-passphrase-option"
              />
            </v-radio-group>
            <v-textarea
              v-if="recipient === 'public_key'"
              id="recovery-export-key"
              v-model="publicKey"
              :label="t('recoveryExport.publicKey')"
              rows="6"
              autocomplete="off"
              spellcheck="false"
              :error-messages="touched && error ? [t(error)] : []"
            />
            <template v-else>
              <p data-testid="recovery-export-passphrase-note">
                {{ t('recoveryExport.passphraseNote') }}
              </p>
              <v-text-field
                id="recovery-export-passphrase"
                v-model="passphrase"
                type="password"
                :label="t('recoveryExport.passphrase')"
                autocomplete="new-password"
                :hint="t('recoveryExport.strength.' + strength)"
                persistent-hint
                data-testid="recovery-export-strength"
              />
              <v-text-field
                id="recovery-export-repeat"
                v-model="repeat"
                type="password"
                :label="t('recoveryExport.passphraseRepeat')"
                autocomplete="new-password"
                :error-messages="touched && error ? [t(error)] : []"
              />
            </template>
            <p class="text-medium-emphasis">
              {{ t('recoveryExport.limit') }}
            </p>
            <v-alert
              v-if="problem"
              type="error"
              variant="tonal"
              density="compact"
              role="alert"
            >
              {{ problemText(problem) }}
            </v-alert>
            <div class="form-actions">
              <v-btn
                type="button"
                variant="tonal"
                @click="close"
              >
                {{ t('common.cancel') }}
              </v-btn>
              <v-btn
                type="submit"
                color="primary"
                :loading="pending"
                :disabled="pending"
                data-testid="recovery-export-submit"
              >
                {{ t('recoveryExport.submit') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>
  </div>
</template>
