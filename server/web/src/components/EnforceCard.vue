<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useConfirm } from '../composables/useConfirm'
import { enforceDevice } from '../lib/devices'
import { useProblemText } from '../lib/problems'

/**
 * Enable enforcement of an adopted, report-only device (plan M11 decisions 42 and 43): styled like a danger zone row,
 * confirmed in the modal with the typed hostname (ADR 0018 high-risk class); the server checks the hostname again.
 * The success message stays once the device is enforced and the action is gone.
 */
const props = defineProps<{ deviceId: string; hostname: string; reportOnly: boolean }>()
const emit = defineEmits<{ changed: [] }>()

const { t } = useI18n()
const confirm = useConfirm()
const problemText = useProblemText()
const problem = ref('')
const notice = ref('')

async function enable(): Promise<void> {
  problem.value = ''
  notice.value = ''
  const answer = await confirm({
    title: t('devices.reportOnly.enforce.confirmTitle', { hostname: props.hostname }),
    message: t('devices.reportOnly.enforce.confirm'),
    confirmLabel: t('devices.reportOnly.enforce.label'),
    destructive: true,
    requireTypedText: props.hostname,
  })
  if (!answer) return
  const res = await enforceDevice(props.deviceId, props.hostname)
  if (res) {
    problem.value = res.problem
    return
  }
  notice.value = t('devices.reportOnly.enforce.done')
  emit('changed')
}
</script>

<template>
  <section
    v-if="reportOnly || notice"
    class="pd-danger pd-device-wide"
    :aria-label="t('devices.reportOnly.enforce.title')"
    data-testid="enforce-card"
  >
    <div
      v-if="reportOnly"
      class="pd-danger-row"
    >
      <div class="pd-danger-text">
        <h2 class="pd-danger-row-title">
          {{ t('devices.reportOnly.enforce.title') }}
        </h2>
        <p>{{ t('devices.reportOnly.enforce.explanation') }}</p>
      </div>
      <v-btn
        color="error"
        variant="flat"
        data-testid="enforce-device"
        @click="enable"
      >
        {{ t('devices.reportOnly.enforce.label') }}
      </v-btn>
    </div>
    <p
      v-if="notice"
      role="status"
      class="pd-danger-alert"
    >
      {{ notice }}
    </p>
    <p
      v-if="problem"
      class="form-error pd-danger-alert"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
  </section>
</template>
