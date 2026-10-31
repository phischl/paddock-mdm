<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PrivacySettings, PrivacySettingsUpdate } from '../api/client'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import {
  getPrivacySettings, retiredInventoryDaysMax, retiredInventoryDaysMin, savePrivacySettings, validRetiredInventoryDays,
} from '../lib/privacy'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/**
 * The organization's privacy settings (ADR 0032 §2, plan M10 decision 10): how long the inventory of a retired device
 * is kept and whether audit searches and inventory views are recorded. Only organization administrators change them.
 */
const { t, locale } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const session = useSessionStore()

const form = ref<PrivacySettingsUpdate | null>(null)
const updatedAt = ref('')
const problem = ref('')
const saved = ref(false)
const touched = ref(false)
const daysInvalid = computed(() => !!form.value && !validRetiredInventoryDays(form.value.retired_inventory_days))
const daysMessage = computed(() =>
  touched.value && daysInvalid.value
    ? [t('privacySettings.retiredInventoryDaysRange', { min: retiredInventoryDaysMin, max: retiredInventoryDaysMax })]
    : [],
)

function apply(s: PrivacySettings): void {
  const { updated_at: at, ...rest } = s
  form.value = rest
  updatedAt.value = at
}

async function save(): Promise<void> {
  touched.value = true
  problem.value = ''
  saved.value = false
  if (!form.value || daysInvalid.value) return
  const res = await savePrivacySettings(form.value)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}

onMounted(async () => {
  const s = await getPrivacySettings()
  if (typeof s === 'string') problem.value = s
  else apply(s)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('privacySettings.title') }}</h1>
    <p class="summary">
      {{ t('privacySettings.intro') }}
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
        <legend>{{ t('privacySettings.retention') }}</legend>
        <v-text-field
          id="retired-inventory-days"
          v-model.number="form.retired_inventory_days"
          type="number"
          :min="retiredInventoryDaysMin"
          :max="retiredInventoryDaysMax"
          :label="t('privacySettings.retiredInventoryDays')"
          :suffix="t('privacySettings.days')"
          :hint="t('privacySettings.retiredInventoryDaysHint')"
          persistent-hint
          :error-messages="daysMessage"
          data-testid="retired-inventory-days"
        />
      </fieldset>
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('privacySettings.recording') }}</legend>
        <v-switch
          id="audit-search-recorded"
          v-model="form.audit_search_recorded"
          :label="t('privacySettings.auditSearchRecorded')"
          :hint="t('privacySettings.auditSearchRecordedHint')"
          persistent-hint
          color="primary"
          inset
          data-testid="audit-search-recorded"
        />
        <v-switch
          id="inventory-view-recorded"
          v-model="form.inventory_view_recorded"
          :label="t('privacySettings.inventoryViewRecorded')"
          :hint="t('privacySettings.inventoryViewRecordedHint')"
          persistent-hint
          color="primary"
          inset
          data-testid="inventory-view-recorded"
        />
      </fieldset>
      <p
        v-if="!session.canDelete"
        class="pd-type-caption pd-muted"
        data-testid="privacy-read-only"
      >
        {{ t('privacySettings.readOnly') }}
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
          data-testid="save-privacy-settings"
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
      data-testid="privacy-saved"
    >
      {{ t('privacySettings.saved') }}
    </v-snackbar>
  </section>
</template>
