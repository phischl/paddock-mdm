<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatDateTime } from '../lib/format'
import {
  getPatchSla, savePatchSla, slaDaysMax, slaDaysMin, slaFields, validSlaDays, type PatchSlaSettings, type PatchSlaSettingsUpdate,
} from '../lib/patchCompliance'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/**
 * The organization's patch SLA (plan M13c decision 17): how many days a vulnerability with a fixed version may stay
 * open per severity before the patch compliance report counts it as breached. Only organization administrators change
 * it.
 */
const { t, locale } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const session = useSessionStore()

const form = ref<PatchSlaSettingsUpdate | null>(null)
const updatedAt = ref('')
const problem = ref('')
const saved = ref(false)
const touched = ref(false)
const invalid = computed(() => {
  const f = form.value
  return !!f && slaFields.some((k) => !validSlaDays(f[k]))
})

function message(field: (typeof slaFields)[number]): string[] {
  return touched.value && form.value && !validSlaDays(form.value[field])
    ? [t('patchSla.range', { min: slaDaysMin, max: slaDaysMax })]
    : []
}

function apply(s: PatchSlaSettings): void {
  const { updated_at: at, ...rest } = s
  form.value = rest
  updatedAt.value = at
}

async function save(): Promise<void> {
  touched.value = true
  problem.value = ''
  saved.value = false
  if (!form.value || invalid.value) return
  const res = await savePatchSla(form.value)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}

onMounted(async () => {
  const s = await getPatchSla()
  if (typeof s === 'string') problem.value = s
  else apply(s)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('patchSla.title') }}</h1>
    <p class="summary">
      {{ t('patchSla.intro') }}
    </p>
    <p
      v-if="updatedAt"
      class="summary"
    >
      {{ t('loginSettings.updatedAt', { at: formatDateTime(updatedAt, locale) }) }}
    </p>
    <form
      v-if="form"
      class="form settings-form"
      novalidate
      @submit.prevent="run(save)"
    >
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('patchSla.legend') }}</legend>
        <v-text-field
          v-for="f in slaFields"
          :id="'patch-sla-' + f"
          :key="f"
          v-model.number="form[f]"
          type="number"
          :min="slaDaysMin"
          :max="slaDaysMax"
          :label="t('patchSla.fields.' + f)"
          :suffix="t('privacySettings.days')"
          :error-messages="message(f)"
          :data-testid="'patch-sla-' + f"
        />
        <p class="pd-type-caption pd-muted">
          {{ t('patchSla.hint') }}
        </p>
      </fieldset>
      <p
        v-if="!session.canDelete"
        class="pd-type-caption pd-muted"
        data-testid="patch-sla-read-only"
      >
        {{ t('patchSla.readOnly') }}
      </p>
      <p
        v-if="problem"
        class="form-error"
        role="alert"
      >
        {{ problemText(problem) }}
      </p>
      <div
        v-if="session.canDelete"
        class="form-actions"
      >
        <v-btn
          type="submit"
          :loading="pending"
          :disabled="pending"
          color="primary"
          data-testid="save-patch-sla"
        >
          {{ t('common.save') }}
        </v-btn>
      </div>
    </form>
    <p
      v-else-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <v-snackbar
      v-model="saved"
      color="success"
      data-testid="patch-sla-saved"
    >
      {{ t('patchSla.saved') }}
    </v-snackbar>
  </section>
</template>
