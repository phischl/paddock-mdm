<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Finding, FindingResolution } from '../api/client'
import {
  findingResolutions, maxFindingExternalRef, maxFindingReason, validateClose, type CloseInput,
} from '../lib/findings'
import { useProblemText } from '../lib/problems'

/**
 * Closes a finding with a resolution and a required reason (plan M9 decision 35). accepted_risk needs an
 * administrator: operators see it disabled with the hint. The reason is audit evidence, so the dialog asks for
 * facts and ticket references, not personal judgements.
 */
const props = defineProps<{
  modelValue: boolean
  finding: Finding | null
  admin: boolean
  problem: string
  pending: boolean
}>()
const emit = defineEmits<{
  submit: [input: CloseInput]
  cancel: []
}>()

const { t } = useI18n()
const problemText = useProblemText()
const resolution = ref<FindingResolution>('resolved')
const reason = ref('')
const externalRef = ref('')
const touched = ref(false)

const errors = computed(() => validateClose({ resolution: resolution.value, reason: reason.value, externalRef: externalRef.value }))
const invalid = computed(() => !!errors.value.reason || !!errors.value.externalRef)

function submit(): void {
  touched.value = true
  if (invalid.value) return
  emit('submit', { resolution: resolution.value, reason: reason.value, externalRef: externalRef.value })
}

const disabled = (r: FindingResolution) => r === 'accepted_risk' && !props.admin
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="36rem"
    :aria-label="t('findings.close.title')"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
  >
    <v-card
      :title="t('findings.close.title')"
      data-testid="finding-close-dialog"
    >
      <v-card-text>
        <p>{{ t('findings.close.message', { code: finding?.code ?? '', hostname: finding?.hostname ?? '' }) }}</p>
        <v-radio-group
          v-model="resolution"
          :label="t('findings.close.resolution')"
          data-testid="finding-resolution"
        >
          <v-radio
            v-for="r in findingResolutions"
            :key="r"
            :value="r"
            :label="t('findings.resolutions.' + r)"
            :disabled="disabled(r)"
            :data-testid="'finding-resolution-' + r"
          />
        </v-radio-group>
        <p
          v-if="!admin"
          class="pd-type-caption pd-muted"
          data-testid="finding-accepted-risk-hint"
        >
          {{ t('findings.close.acceptedRiskHint') }}
        </p>
        <v-textarea
          v-model="reason"
          :label="t('findings.close.reason')"
          :hint="t('findings.close.reasonHint')"
          persistent-hint
          :counter="maxFindingReason"
          :error-messages="touched && errors.reason ? [t(errors.reason)] : []"
          rows="3"
          auto-grow
          autocomplete="off"
          data-testid="finding-reason"
          @keydown.enter.stop
        />
        <v-text-field
          v-model="externalRef"
          :label="t('findings.close.externalRef')"
          :hint="t('findings.close.externalRefHint')"
          persistent-hint
          :counter="maxFindingExternalRef"
          :error-messages="errors.externalRef ? [t(errors.externalRef)] : []"
          autocomplete="off"
          data-testid="finding-external-ref"
          @keydown.enter.prevent
        />
        <p
          v-if="problem"
          class="form-error"
          role="alert"
        >
          {{ problemText(problem) }}
        </p>
        <div class="form-actions">
          <v-btn
            variant="tonal"
            data-testid="finding-close-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="primary"
            variant="flat"
            :loading="pending"
            :disabled="pending"
            data-testid="finding-close-submit"
            @click="submit"
          >
            {{ t('findings.close.submit') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
