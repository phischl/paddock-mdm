<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SoftwareArchitecture, SoftwareSource } from '../api/client'
import { stepUpRequired } from '../lib/stepUp'
import { useProblemText } from '../lib/problems'
import {
  groupFingerprint, normalizeFingerprint, saveSoftwareSource, splitTokens, splitUris, validateSource, type SourceInput,
} from '../lib/software'
import { hasErrors } from '../lib/validation'

/**
 * Create and edit form of a package source. It sends the write itself: a refusal with step_up_required is not an
 * error but asks the page to run the step-up and repeat the write (emit step-up with the input), because adding or
 * changing a source is a root-equivalent change (plan M13a decision 30).
 */
const props = withDefaults(
  defineProps<{ initial?: SoftwareSource | null; draft?: SourceInput | null; initialProblem?: string }>(),
  { initial: null, draft: null, initialProblem: '' },
)
const emit = defineEmits<{ saved: []; cancel: []; 'step-up': [input: SourceInput, keyChanged: boolean] }>()

const { t } = useI18n()
const problemText = useProblemText()
// A draft is what the administrator typed before a step-up round trip; it wins over the stored source so a refusal
// after the resume does not cost the input.
const draft = props.draft
const slug = ref(draft?.slug ?? props.initial?.slug ?? '')
const name = ref(draft?.name ?? props.initial?.name ?? '')
const uris = ref((draft?.uris ?? props.initial?.uris ?? []).join('\n'))
const suites = ref((draft?.suites ?? props.initial?.suites ?? []).join(' '))
const components = ref((draft?.components ?? props.initial?.components ?? []).join(' '))
const architectures = ref<SoftwareArchitecture[]>([...(draft?.architectures ?? props.initial?.architectures ?? [])])
const signingKey = ref(draft?.signingKey ?? props.initial?.signing_key ?? '')
const fingerprint = ref(draft ? draft.fingerprint : props.initial ? groupFingerprint(props.initial.fingerprint) : '')
const touched = ref(false)
const pending = ref(false)
const problem = ref(props.initialProblem)

const input = computed<SourceInput>(() => ({
  slug: slug.value.trim(),
  name: name.value,
  uris: splitUris(uris.value),
  suites: splitTokens(suites.value),
  components: splitTokens(components.value),
  architectures: architectures.value,
  signingKey: signingKey.value,
  fingerprint: fingerprint.value,
}))
const errors = computed(() => validateSource(input.value, props.initial === null))
const keyChanged = computed(
  () => !props.initial || signingKey.value !== props.initial.signing_key || normalizeFingerprint(fingerprint.value) !== props.initial.fingerprint,
)
const fingerprintProblem = computed(() => (problem.value === 'fingerprint_mismatch' ? problemText(problem.value) : ''))
const otherProblem = computed(() => (problem.value && problem.value !== 'fingerprint_mismatch' ? problemText(problem.value) : ''))

function fieldErrors(key: string | undefined, extra = ''): string[] {
  return [...(touched.value && key ? [t(key)] : []), ...(extra ? [extra] : [])]
}

async function submit(): Promise<void> {
  touched.value = true
  problem.value = ''
  if (hasErrors(errors.value) || pending.value) return
  pending.value = true
  try {
    const code = await saveSoftwareSource(props.initial?.id ?? null, input.value, keyChanged.value)
    if (code === stepUpRequired) {
      emit('step-up', input.value, keyChanged.value)
      return
    }
    problem.value = code ?? ''
    if (!code) emit('saved')
  } finally {
    pending.value = false
  }
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-text-field
      id="source-name"
      v-model="name"
      :label="t('software.sources.name')"
      autocomplete="off"
      :error-messages="fieldErrors(errors.name)"
      data-testid="source-name"
    />
    <v-text-field
      id="source-slug"
      v-model="slug"
      :label="t('software.sources.slug')"
      :hint="t('software.sources.slugHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      :disabled="initial !== null"
      :error-messages="fieldErrors(errors.slug)"
      data-testid="source-slug"
    />
    <v-textarea
      id="source-uris"
      v-model="uris"
      :label="t('software.sources.uris')"
      :hint="t('software.sources.urisHint')"
      persistent-hint
      rows="2"
      auto-grow
      spellcheck="false"
      :error-messages="fieldErrors(errors.uris)"
      data-testid="source-uris"
    />
    <v-text-field
      id="source-suites"
      v-model="suites"
      :label="t('software.sources.suites')"
      :hint="t('software.sources.suitesHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      :error-messages="fieldErrors(errors.suites)"
      data-testid="source-suites"
    />
    <v-text-field
      id="source-components"
      v-model="components"
      :label="t('software.sources.components')"
      :hint="t('software.sources.componentsHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      :error-messages="fieldErrors(errors.components)"
      data-testid="source-components"
    />
    <fieldset class="source-architectures">
      <legend>{{ t('software.sources.architectures') }}</legend>
      <v-checkbox
        v-for="arch in ['amd64', 'arm64']"
        :key="arch"
        v-model="architectures"
        :value="arch"
        :label="arch"
        density="compact"
        hide-details
        :data-testid="'source-arch-' + arch"
      />
      <p class="summary">
        {{ t('software.sources.architecturesHint') }}
      </p>
    </fieldset>
    <v-textarea
      id="source-key"
      v-model="signingKey"
      :label="t('software.sources.signingKey')"
      rows="6"
      auto-grow
      spellcheck="false"
      class="mono"
      :error-messages="fieldErrors(errors.signingKey)"
      data-testid="source-key"
    />
    <v-text-field
      id="source-fingerprint"
      v-model="fingerprint"
      :label="t('software.sources.fingerprint')"
      :hint="t('software.sources.fingerprintHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      class="mono"
      :error-messages="fieldErrors(errors.fingerprint, fingerprintProblem)"
      data-testid="source-fingerprint"
      @blur="fingerprint = groupFingerprint(fingerprint)"
    />
    <p
      v-if="initial?.weak_key"
      class="summary"
      data-testid="source-weak-key"
    >
      {{ t('software.sources.weakKey') }}
    </p>
    <p
      v-if="otherProblem"
      class="form-error"
      role="alert"
    >
      {{ otherProblem }}
    </p>
    <div class="form-actions">
      <v-btn
        type="button"
        variant="tonal"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </v-btn>
      <v-btn
        type="submit"
        color="primary"
        :loading="pending"
        :disabled="pending"
        data-testid="save-source"
      >
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>
