<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import AutoUnsealDisclaimerDialog from '../components/AutoUnsealDisclaimerDialog.vue'
import { useConfirm } from '../composables/useConfirm'
import {
  autoUnsealAlert,
  disableAutoUnseal,
  enableAutoUnseal,
  getAutoUnseal,
  type AutoUnsealAcknowledgement,
  type AutoUnsealStatus,
} from '../lib/autoUnseal'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'

/** Step-up actions of the page (plan M8u §6.5); the setting is a singleton, so the target is fixed. */
const enableAction = 'auto-unseal-enable'
const disableAction = 'auto-unseal-disable'
const stepUpTarget = 'setting'

const { t, locale } = useI18n()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const status = ref<AutoUnsealStatus | null>(null)
const problem = ref('')
const pending = ref(false)
const dialogOpen = ref(false)

const alert = computed(() => (status.value ? autoUnsealAlert(status.value) : null))
const outdated = computed(
  () =>
    status.value?.state === 'enabled' &&
    status.value.acknowledgement_version !== null &&
    status.value.acknowledgement_version !== status.value.disclaimer_version,
)

function at(iso: string | null | undefined): string {
  return iso ? formatDateTime(iso, locale.value) : ''
}

async function load(): Promise<void> {
  const res = await getAutoUnseal()
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  status.value = res
}

onMounted(async () => {
  await load()
  const enable = resumeStepUp<AutoUnsealAcknowledgement>(enableAction, stepUpTarget)
  const disable = resumeStepUp<null>(disableAction, stepUpTarget)
  const resumed = enable ?? disable
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  if (enable && !enable.failed) await runEnable(enable.payload, false)
  else await runDisable(false)
})

/** Applies the answer of enable or disable: the new status, or the problem (a stale disclaimer reloads the page). */
async function settle(res: AutoUnsealStatus | string): Promise<void> {
  if (typeof res !== 'string') {
    status.value = res
    return
  }
  problem.value = res
  if (res === 'disclaimer_outdated') await load()
}

async function runEnable(input: AutoUnsealAcknowledgement, stepUp: boolean): Promise<void> {
  problem.value = ''
  pending.value = true
  const res = await enableAutoUnseal(input)
  pending.value = false
  dialogOpen.value = false
  if (res === stepUpRequired && stepUp) {
    startStepUp(enableAction, stepUpTarget, input)
    return
  }
  await settle(res)
}

async function runDisable(stepUp: boolean): Promise<void> {
  problem.value = ''
  pending.value = true
  const res = await disableAutoUnseal()
  pending.value = false
  if (res === stepUpRequired && stepUp) {
    startStepUp(disableAction, stepUpTarget)
    return
  }
  await settle(res)
}

async function onDisable(): Promise<void> {
  const confirmed = await confirm({
    title: t('openbao.disableConfirmTitle'),
    message: t('openbao.disableConfirmMessage'),
    confirmLabel: t('openbao.disable'),
    destructive: false,
  })
  if (!confirmed) return
  await runDisable(true)
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('openbao.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('openbao.summary') }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
      data-testid="openbao-problem"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="status">
      <v-alert
        v-if="alert"
        :type="alert === 'sharesLeft' ? 'warning' : 'info'"
        variant="tonal"
        class="openbao-alert"
        :data-testid="'openbao-alert-' + alert"
      >
        {{ t('openbao.alerts.' + alert) }}
      </v-alert>

      <div class="openbao-sections">
        <section
          class="openbao-section"
          data-testid="openbao-seal"
        >
          <h2 class="pd-type-section">
            {{ t('openbao.seal.title') }}
          </h2>
          <p v-if="!status.seal.reachable">
            {{ t('openbao.seal.unreachable') }}
          </p>
          <template v-else>
            <p>{{ status.seal.sealed ? t('openbao.seal.sealed') : t('openbao.seal.unsealed') }}</p>
            <p>
              {{ t('openbao.seal.threshold', { threshold: status.seal.threshold, shares: status.seal.shares, type: status.seal.type }) }}
            </p>
          </template>
        </section>

        <section
          class="openbao-section"
          data-testid="openbao-setting"
        >
          <h2 class="pd-type-section">
            {{ t('openbao.setting.title') }}
          </h2>
          <p v-if="status.state === 'enabled'">
            {{ t('openbao.setting.on', { by: status.acknowledged_by ?? '', at: at(status.acknowledged_at), version: status.acknowledgement_version ?? '' }) }}
          </p>
          <p v-else>
            {{ t('openbao.setting.off') }}
          </p>
          <p
            v-if="outdated"
            data-testid="openbao-outdated"
          >
            {{ t('openbao.setting.outdated') }}
          </p>
          <p v-if="status.state === 'disabled' && status.disabled_by">
            {{ t('openbao.setting.disabledBy', { by: status.disabled_by, at: at(status.disabled_at) }) }}
          </p>
        </section>

        <section
          class="openbao-section"
          data-testid="openbao-unsealer"
        >
          <h2 class="pd-type-section">
            {{ t('openbao.unsealer.title') }}
          </h2>
          <p v-if="!status.unsealer.running">
            {{ t('openbao.unsealer.notRunning') }}
          </p>
          <p v-else>
            {{ status.unsealer.shares_present ? t('openbao.unsealer.runningWithShares') : t('openbao.unsealer.runningNoShares') }}
          </p>
          <p v-if="status.unsealer.seen_at">
            {{ t('openbao.unsealer.seenAt', { at: at(status.unsealer.seen_at) }) }}
          </p>
          <p v-if="status.unsealer.last_unseal_at">
            {{ t('openbao.unsealer.lastUnseal', { at: at(status.unsealer.last_unseal_at), count: status.unsealer.unseal_count }) }}
          </p>
          <p v-else>
            {{ t('openbao.unsealer.neverUnsealed') }}
          </p>
          <p v-if="status.unsealer.last_failure_at && status.unsealer.last_failure_reason">
            {{ t('openbao.unsealer.lastFailure', { at: at(status.unsealer.last_failure_at), reason: t('openbao.unsealer.reason.' + status.unsealer.last_failure_reason) }) }}
          </p>
        </section>
      </div>

      <div class="form-actions openbao-actions">
        <v-btn
          v-if="status.state === 'disabled'"
          color="error"
          :loading="pending"
          :disabled="pending"
          data-testid="openbao-enable"
          @click="dialogOpen = true"
        >
          {{ t('openbao.enable') }}
        </v-btn>
        <v-btn
          v-else
          variant="tonal"
          :loading="pending"
          :disabled="pending"
          data-testid="openbao-disable"
          @click="onDisable"
        >
          {{ t('openbao.disable') }}
        </v-btn>
      </div>

      <AutoUnsealDisclaimerDialog
        :model-value="dialogOpen"
        :version="status.disclaimer_version"
        :pending="pending"
        @confirm="(input) => runEnable(input, true)"
        @cancel="dialogOpen = false"
      />
    </template>
  </section>
</template>

<style scoped>
.openbao-alert {
  margin-bottom: var(--pd-space-4);
}

.openbao-sections {
  display: grid;
  gap: var(--pd-space-4);
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
}

.openbao-section h2 {
  margin-bottom: var(--pd-space-2);
}

.openbao-section p + p {
  margin-top: var(--pd-space-1);
}

.openbao-actions {
  margin-top: var(--pd-space-6);
}
</style>
