<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import StatusChip from './StatusChip.vue'
import { useProblemText } from '../lib/problems'
import { getUpgradeCheck, upgradeItem, upgradeItemStatus, type UpgradeCheck } from '../lib/upgradeCheck'
import { useSessionStore } from '../stores/session'

/**
 * The information card *Upgrade* on the platform administrator's landing page (plan M16 decision 13, PDK-746): the
 * support window of the release the server runs, the active devices whose agent is outside it and the backup state.
 * It reads GET /api/platform/v1/upgrade-check and offers no action; the upgrade itself is a host command.
 */
const { t } = useI18n()
const session = useSessionStore()
const problemText = useProblemText()
const report = ref<UpgradeCheck | null>(null)
const problem = ref('')
const loading = ref(false)

// The list of the report holds at most 100 devices; the agents item counts all of them.
const listedHosts = 5
const outside = computed(() => report.value?.agents_outside ?? [])
const hosts = computed(() => outside.value.slice(0, listedHosts).map((a) => a.hostname).join(', '))
const more = computed(() => Math.max(0, outside.value.length - listedHosts))
const agents = computed(() => (report.value ? upgradeItem(report.value, 'agents') : undefined))
const backups = computed(() => (report.value ? upgradeItem(report.value, 'backups') : undefined))
const visible = computed(() => session.isPlatform && !!session.me)

async function load(): Promise<void> {
  const version = session.me?.server_version ?? ''
  loading.value = true
  const res = await getUpgradeCheck(version)
  loading.value = false
  if (typeof res === 'string') {
    problem.value = res
  } else {
    report.value = res
  }
}

onMounted(() => {
  if (visible.value) void load()
})
</script>

<template>
  <section
    v-if="visible"
    class="pd-panel pd-upgrade"
    data-testid="upgrade-card"
    aria-labelledby="upgrade-title"
    :aria-busy="loading"
  >
    <header class="pd-panel-header">
      <h2
        id="upgrade-title"
        class="pd-type-section"
      >
        {{ t('upgradeCard.title') }}
      </h2>
      <span
        v-if="report"
        class="pd-type-caption pd-muted"
        data-testid="upgrade-version"
      >{{ t('upgradeCard.version', { version: report.target_version }) }}</span>
    </header>
    <div class="pd-panel-body">
      <v-alert
        v-if="problem"
        type="info"
        variant="tonal"
        density="compact"
        data-testid="upgrade-problem"
      >
        {{ problem === 'invalid_request' ? t('upgradeCard.unknownVersion') : problemText(problem) }}
      </v-alert>
      <dl
        v-else-if="report"
        class="pd-upgrade-list"
      >
        <div data-testid="upgrade-window">
          <dt>{{ t('upgradeCard.window') }}</dt>
          <dd>{{ report.window.join(', ') }}</dd>
        </div>
        <div data-testid="upgrade-agents">
          <dt>{{ t('upgradeCard.agents') }}</dt>
          <dd>
            <StatusChip
              v-if="agents"
              :status="upgradeItemStatus(agents)"
              :label="t('upgradeCard.status.' + agents.status)"
            />
            <span v-if="outside.length === 0">{{ t('upgradeCard.noneOutside') }}</span>
            <span v-else>
              {{ t('upgradeCard.outside', { count: outside.length }) }}
              <span class="pd-muted">{{ hosts }}<template v-if="more > 0"> {{ t('upgradeCard.more', { count: more }) }}</template></span>
            </span>
          </dd>
        </div>
        <div
          v-if="backups"
          data-testid="upgrade-backups"
        >
          <dt>{{ t('upgradeCard.backups') }}</dt>
          <dd>
            <StatusChip
              :status="upgradeItemStatus(backups)"
              :label="t('upgradeCard.status.' + backups.status)"
            />
            <!-- The detail is the server's own sentence; it names devices, versions and times, not UI text. -->
            <span class="pd-muted">{{ backups.detail }}</span>
          </dd>
        </div>
      </dl>
      <p
        v-else
        class="pd-muted"
        data-testid="upgrade-loading"
      >
        {{ t('upgradeCard.loading') }}
      </p>
    </div>
  </section>
</template>

<style scoped>
.pd-upgrade {
  margin-bottom: var(--pd-space-4, 16px);
}

.pd-upgrade-list {
  display: grid;
  gap: 0.75em;
  margin: 0;
}

.pd-upgrade-list dt {
  font-size: 0.8125rem;
  opacity: 0.75;
}

.pd-upgrade-list dd {
  margin: 0;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5em;
  align-items: center;
}
</style>
