<script setup lang="ts">
// The Diagnostics tab of a device (ADR 0048, plan M12 decision 14): its bundles, and the request with a reason.
import { computed, inject, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DiagnosticsList from '../components/DiagnosticsList.vue'
import { contentListUrl, listDeviceDiagnostics, maxReason, requestDiagnostics, validReason } from '../lib/diagnostics'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import { useProblemText } from '../lib/problems'
import { usePending } from '../composables/usePending'

const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceDiagnostics outside the device frame')
const { t } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const { pending, run } = usePending()
const id = computed(() => String(route.params.id))
const fetch = computed(() => listDeviceDiagnostics(id.value))
const list = ref<{ reload: () => Promise<void> } | null>(null)
const canRequest = computed(() => page.device.value?.state === 'active')

const open = ref(false)
const reason = ref('')
const touched = ref(false)
const problem = ref('')
const requested = ref(false)
const reasonError = computed(() => (validReason(reason.value) ? '' : t('diagnostics.request.reasonInvalid', { max: maxReason })))

function openRequest(): void {
  reason.value = ''
  touched.value = false
  problem.value = ''
  requested.value = false
  open.value = true
}

async function submit(): Promise<void> {
  touched.value = true
  problem.value = ''
  if (reasonError.value) return
  const res = await requestDiagnostics(id.value, reason.value)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  open.value = false
  requested.value = true
  void list.value?.reload()
}
</script>

<template>
  <div class="pd-device-tab">
    <div class="page-header">
      <p class="summary">
        {{ t('diagnostics.summary') }}
      </p>
      <v-btn
        color="primary"
        :disabled="!canRequest"
        data-testid="diagnostics-request"
        @click="openRequest"
      >
        {{ t('diagnostics.request.open') }}
      </v-btn>
    </div>
    <v-alert
      v-if="requested"
      type="success"
      variant="tonal"
      data-testid="diagnostics-requested"
    >
      {{ t('diagnostics.request.done') }}
    </v-alert>
    <DiagnosticsList
      ref="list"
      :fetch="fetch"
    />

    <v-dialog
      v-model="open"
      max-width="36rem"
      :aria-label="t('diagnostics.request.title')"
    >
      <v-card :title="t('diagnostics.request.title')">
        <v-card-text>
          <form
            class="form"
            novalidate
            @submit.prevent="run(submit)"
          >
            <p data-testid="diagnostics-request-text">
              {{ t('diagnostics.request.explanation') }}
            </p>
            <p>
              <a
                :href="contentListUrl"
                target="_blank"
                rel="noopener"
              >{{ t('diagnostics.request.contentList') }}</a>
            </p>
            <v-textarea
              v-model="reason"
              :label="t('diagnostics.reason')"
              :counter="maxReason"
              rows="2"
              auto-grow
              :error-messages="touched && reasonError ? [reasonError] : []"
              data-testid="diagnostics-reason"
            />
            <p
              v-if="problem"
              class="form-error"
              role="alert"
              data-testid="diagnostics-request-problem"
            >
              {{ problemText(problem) }}
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
                :loading="pending"
                data-testid="diagnostics-request-submit"
              >
                {{ t('diagnostics.request.submit') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>
  </div>
</template>
