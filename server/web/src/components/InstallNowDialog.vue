<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useProblemText } from '../lib/problems'
import { maxInstallPackages, parsePackages, validPackage } from '../lib/updates'

/**
 * Asks for the packages of an install-now request (plan M5b decision 3) and runs it through install, which returns
 * null or a problem code with its detail (package_on_hold names the held package).
 */
const props = defineProps<{
  title: string
  install: (packages: string[]) => Promise<{ problem: string; detail?: string } | null>
}>()
const open = defineModel<boolean>({ required: true })
const emit = defineEmits<{ done: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const text = ref('')
const touched = ref(false)
const problem = ref<{ problem: string; detail?: string } | null>(null)
const busy = ref(false)
const packages = computed(() => parsePackages(text.value))
const error = computed(() => {
  if (packages.value.length === 0 || packages.value.length > maxInstallPackages) return t('updates.installNow.countInvalid', { max: maxInstallPackages })
  const bad = packages.value.find((p) => !validPackage(p))
  return bad ? t('updates.holds.packageInvalid') + ' (' + bad + ')' : ''
})

const problemMessage = computed(() =>
  problem.value ? [problemText(problem.value.problem), problem.value.detail].filter(Boolean).join(' – ') : '',
)

async function submit(): Promise<void> {
  touched.value = true
  problem.value = null
  if (error.value) return
  busy.value = true
  problem.value = await props.install(packages.value)
  busy.value = false
  if (problem.value) return
  text.value = ''
  touched.value = false
  open.value = false
  emit('done')
}
</script>

<template>
  <v-dialog
    v-model="open"
    max-width="36rem"
    :aria-label="title"
  >
    <v-card :title="title">
      <v-card-text>
        <form
          class="form"
          novalidate
          @submit.prevent="submit"
        >
          <p>{{ t('updates.installNow.explanation') }}</p>
          <v-textarea
            id="install-packages"
            v-model="text"
            :label="t('updates.installNow.packages')"
            :hint="t('updates.installNow.packagesHint', { max: maxInstallPackages })"
            persistent-hint
            rows="2"
            auto-grow
            spellcheck="false"
            :error-messages="touched && error ? [error] : []"
            data-testid="install-packages"
          />
          <p
            v-if="problem"
            class="form-error"
            role="alert"
            data-testid="install-problem"
          >
            {{ problemMessage }}
          </p>
          <div class="form-actions">
            <v-btn
              type="button"
              variant="tonal"
              @click="open = false"
            >
              {{ t('common.cancel') }}
            </v-btn>
            <v-btn
              type="submit"
              color="primary"
              :loading="busy"
              data-testid="install-submit"
            >
              {{ t('updates.installNow.submit') }}
            </v-btn>
          </div>
        </form>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
