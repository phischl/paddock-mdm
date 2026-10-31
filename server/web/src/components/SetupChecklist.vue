<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { gettingStartedGuide, loadSetupSteps, type SetupStep } from '../lib/setupChecklist'
import { useSessionStore } from '../stores/session'
import { useSetupStore } from '../stores/setup'

/**
 * The setup checklist of the platform administrator (organizations page) and of the organization (overview), PDK-200.
 * Every state is read from list endpoints that already exist; steps that need the host shell link the guide.
 */
const { t } = useI18n()
const session = useSessionStore()
const setup = useSetupStore()
setup.load(session.me?.id ?? '')
const steps = ref<SetupStep[]>([])
const loading = ref(false)

async function ensureLoaded(): Promise<void> {
  if (setup.dismissed || steps.value.length > 0) return
  loading.value = true
  steps.value = await loadSetupSteps({ isPlatform: session.isPlatform, canWrite: session.canWrite })
  loading.value = false
}

onMounted(ensureLoaded)
watch(() => setup.dismissed, ensureLoaded)

const checked = computed(() => steps.value.filter((s) => s.state !== 'manual' && !s.optional))
const doneCount = computed(() => checked.value.filter((s) => s.state === 'done').length)
const visible = computed(() => !!session.me && !setup.dismissed)
</script>

<template>
  <section
    v-if="visible"
    class="pd-panel pd-setup"
    data-testid="setup-checklist"
    aria-labelledby="setup-title"
    :aria-busy="loading"
  >
    <header class="pd-panel-header">
      <h2
        id="setup-title"
        class="pd-type-section"
      >
        {{ t('setup.title') }}
      </h2>
      <span
        v-if="!loading"
        class="pd-type-caption pd-muted"
        data-testid="setup-progress"
      >{{ t('setup.progress', { done: doneCount, total: checked.length }) }}</span>
      <v-btn
        variant="text"
        size="small"
        data-testid="setup-dismiss"
        @click="setup.dismiss()"
      >
        {{ t('setup.dismiss') }}
      </v-btn>
    </header>
    <ol
      v-if="!loading"
      class="pd-setup-steps"
    >
      <li
        v-for="step in steps"
        :key="step.key"
        :data-testid="'setup-step-' + step.key"
        :data-state="step.state"
      >
        <span class="pd-setup-state">{{ t('setup.states.' + step.state) }}</span>
        <RouterLink
          v-if="step.to && step.state !== 'done'"
          :to="step.to"
        >
          {{ t(step.label) }}
        </RouterLink>
        <span v-else>{{ t(step.label) }}</span>
        <template v-if="step.state === 'manual'">
          {{ ' ' }}
          <a
            :href="gettingStartedGuide"
            target="_blank"
            rel="noopener noreferrer"
            data-testid="setup-guide"
          >{{ t('setup.guide') }}</a>
        </template>
      </li>
    </ol>
  </section>
</template>

<style scoped>
.pd-setup {
  margin-bottom: var(--pd-space-4, 16px);
}

.pd-setup-steps {
  margin: 0;
  padding: 0 var(--pd-space-4, 16px) var(--pd-space-4, 16px) calc(var(--pd-space-4, 16px) + 1.5em);
}

.pd-setup-steps li + li {
  margin-top: 0.5em;
}

.pd-setup-state {
  display: inline-block;
  min-width: 7em;
  margin-right: 0.5em;
  font-size: 0.8125rem;
  opacity: 0.75;
}

@media (max-width: 600px) {
  .pd-setup-state {
    display: block;
    min-width: 0;
    margin-right: 0;
  }
}
</style>
