<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { AttentionDevice, AuditEvent, Overview } from '../api/client'
import ActorChip from '../components/ActorChip.vue'
import EmptyState from '../components/EmptyState.vue'
import KpiStrip from '../components/KpiStrip.vue'
import SeverityBar from '../components/SeverityBar.vue'
import SeverityChip from '../components/SeverityChip.vue'
import AttentionChips from '../components/AttentionChips.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import { modifierLabel } from '../composables/useShortcuts'
import { useProblemText } from '../lib/problems'
import { auditText } from '../lib/format'
import { shortcutOf } from '../lib/navigation'
import { getOverview, kpiCells, overviewAttention, recentAuditEvents } from '../lib/overview'
import { outcomeStatus } from '../lib/status'
import { formatAbsolute } from '../lib/time'
import { useSessionStore } from '../stores/session'

/**
 * The overview of the organization (plan M7c decision 28): fleet numbers, attention grouped by device, devices by
 * their worst finding, updates and the agent rollout, recent audit activity. Every number comes from the API.
 */
const { t, te } = useI18n()
const session = useSessionStore()
const problemText = useProblemText()
const overview = ref<Overview | null>(null)
const attention = ref<AttentionDevice[]>([])
const audit = ref<AuditEvent[]>([])
const problem = ref('')
const loading = ref(true)

onMounted(async () => {
  const [o, a, e] = await Promise.all([
    getOverview(),
    overviewAttention().catch(() => null),
    session.canReadAudit ? recentAuditEvents().catch(() => null) : Promise.resolve(null),
  ])
  if (typeof o === 'string') problem.value = o
  else overview.value = o
  attention.value = a?.items.slice(0, 5) ?? []
  audit.value = e?.items.slice(0, 8) ?? []
  loading.value = false
})

const cells = computed(() => (overview.value ? kpiCells(overview.value) : []))
/** The counts of the security review (ADR 0034 decision 7); null hides the banner. */
const review = computed(() => {
  const r = overview.value?.security_review
  return r && r.root_grants + r.sensitive_files + r.denied_files > 0 ? r : null
})
const subtitle = computed(() =>
  overview.value
    ? t('overview.subtitle', {
      org: session.me?.organization?.name ?? '',
      count: overview.value.devices.total,
      time: formatAbsolute(overview.value.generated_at, new Date(overview.value.generated_at), 'second'),
    })
    : '',
)
const agentLine = computed(() => {
  const u = overview.value?.updates
  if (!u?.agent.current_version) return null
  return { version: u.agent.current_version, on: u.agent.on_current, active: overview.value?.devices.active ?? 0 }
})
const agentRollout = computed(() => overview.value?.updates.agent.rollout ?? null)
const latestPublished = computed(() => {
  const a = overview.value?.updates.agent
  return a?.latest_published && a.latest_published !== a.current_version ? a.latest_published : null
})
</script>

<template>
  <section
    class="page pd-overview"
    :aria-busy="loading"
  >
    <h1>{{ t('overview.title') }}</h1>
    <p
      v-if="overview"
      class="summary"
    >
      {{ subtitle }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <div
      v-if="loading"
      class="pd-overview-placeholder"
      aria-hidden="true"
    >
      <div class="pd-placeholder pd-placeholder--strip" />
      <div class="pd-placeholder pd-placeholder--panel" />
    </div>
    <template v-if="overview">
      <v-alert
        v-if="review"
        type="warning"
        variant="tonal"
        class="conflict"
        data-testid="security-review-banner"
      >
        {{ t('overview.securityReview.banner', { rootGrants: review.root_grants, sensitiveFiles: review.sensitive_files, deniedFiles: review.denied_files }) }}
        <RouterLink :to="{ name: 'security-review' }">
          {{ t('overview.securityReview.link') }}
        </RouterLink>
      </v-alert>
      <KpiStrip :cells="cells" />

      <div class="pd-overview-grid">
        <section
          class="pd-panel pd-overview-attention"
          data-testid="overview-attention"
          aria-labelledby="overview-attention-title"
        >
          <header class="pd-panel-header">
            <h2
              id="overview-attention-title"
              class="pd-type-section"
            >
              {{ t('overview.attention.title') }}
            </h2>
            <span class="pd-type-caption pd-muted">{{ t('overview.attention.caption') }}</span>
            <RouterLink
              :to="{ name: 'attention' }"
              class="pd-panel-link"
            >
              {{ t('overview.attention.open') }}
              <kbd
                class="pd-kbd"
                aria-hidden="true"
              >{{ shortcutOf('/attention') }}</kbd>
            </RouterLink>
          </header>
          <EmptyState
            v-if="attention.length === 0"
            icon="circle-check"
            :title="t('attention.empty.title')"
            :description="t('attention.empty.description')"
          />
          <div
            v-else
            class="pd-table-scroll"
          >
            <table class="pd-table">
              <thead>
                <tr>
                  <th scope="col">
                    {{ t('overview.attention.device') }}
                  </th>
                  <th scope="col">
                    {{ t('overview.attention.conditions') }}
                  </th>
                  <th
                    scope="col"
                    class="pd-hide-sm"
                  >
                    {{ t('devices.lastContact') }}
                  </th>
                  <th
                    scope="col"
                    class="pd-hide-sm"
                  >
                    <span class="visually-hidden">{{ t('common.actions') }}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="d in attention"
                  :key="d.device_id"
                >
                  <td class="pd-cell-primary">
                    <RouterLink
                      :to="{ name: 'device', params: { id: d.device_id } }"
                      class="mono pd-truncate"
                      :title="d.hostname"
                    >
                      {{ d.hostname }}
                    </RouterLink>
                    <span
                      v-if="d.os_release.VERSION_ID"
                      class="pd-type-caption pd-muted pd-block"
                    >{{ t('overview.attention.os', { release: d.os_release.VERSION_ID }) }}</span>
                  </td>
                  <td>
                    <AttentionChips :conditions="d.conditions" />
                  </td>
                  <td class="pd-hide-sm">
                    <TimeCell
                      v-if="d.last_contact_at"
                      :iso="d.last_contact_at"
                      mode="relative"
                    />
                    <span
                      v-else
                      class="pd-muted"
                    >{{ t('time.never') }}</span>
                  </td>
                  <td class="pd-cell-actions pd-hide-sm">
                    <v-btn
                      :to="{ name: 'device', params: { id: d.device_id } }"
                      :aria-label="t('attention.open', { action: t('attention.action.' + d.conditions[0].kind), hostname: d.hostname })"
                      size="small"
                    >
                      {{ t('attention.action.' + d.conditions[0].kind) }}
                    </v-btn>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section
          class="pd-panel"
          data-testid="overview-vulnerabilities"
          aria-labelledby="overview-vulnerabilities-title"
        >
          <header class="pd-panel-header">
            <h2
              id="overview-vulnerabilities-title"
              class="pd-type-section"
            >
              {{ t('overview.vulnerabilities.title') }}
            </h2>
            <span class="pd-type-caption pd-muted">{{ t('overview.vulnerabilities.caption') }}</span>
          </header>
          <div class="pd-panel-body">
            <SeverityBar :buckets="overview.vulnerabilities.by_highest_severity" />
            <EmptyState
              v-if="overview.vulnerabilities.top.length === 0"
              icon="bug"
              :title="t('inventory.empty.vulnerabilities.title')"
              :description="t('inventory.empty.vulnerabilities.description')"
            />
            <ul
              v-else
              class="pd-top-cves"
            >
              <li
                v-for="c in overview.vulnerabilities.top"
                :key="c.cve"
              >
                <span class="pd-top-cve-id">
                  <RouterLink
                    :to="{ name: 'vulnerability', params: { cve: c.cve } }"
                    class="mono"
                  >{{ c.cve }}</RouterLink>
                  <span class="pd-type-caption pd-muted mono">{{ c.packages.join(', ') }}</span>
                </span>
                <SeverityChip :severity="c.severity" />
                <span class="pd-tabular mono">{{ t('overview.vulnerabilities.devices', { count: c.devices }) }}</span>
              </li>
            </ul>
          </div>
        </section>

        <section
          class="pd-panel"
          data-testid="overview-updates"
          aria-labelledby="overview-updates-title"
        >
          <header class="pd-panel-header">
            <h2
              id="overview-updates-title"
              class="pd-type-section"
            >
              {{ t('overview.updates.title') }}
            </h2>
          </header>
          <dl class="pd-panel-body pd-facts">
            <div>
              <dt>{{ t('overview.updates.securityOverdue') }}</dt>
              <dd class="mono pd-tabular">
                {{ overview.updates.security_overdue }}
              </dd>
            </div>
            <div>
              <dt>{{ t('overview.updates.rebootRequired') }}</dt>
              <dd class="mono pd-tabular">
                {{ overview.updates.reboot_required }}
              </dd>
            </div>
            <div>
              <dt>
                {{ agentLine ? t('overview.updates.agent', { version: agentLine.version }) : t('overview.updates.agentNone') }}
              </dt>
              <dd
                v-if="agentLine"
                class="mono pd-tabular"
              >
                {{ t('overview.updates.agentOnCurrent', { on: agentLine.on, active: agentLine.active }) }}
              </dd>
              <dd
                v-else
                class="pd-muted"
              >
                –
              </dd>
            </div>
            <div v-if="agentRollout">
              <dt>{{ t('overview.updates.rollout', { version: agentRollout.version }) }}</dt>
              <dd class="mono pd-tabular">
                {{ t('overview.updates.rolloutWave', { wave: agentRollout.wave, waves: agentRollout.waves, percent: agentRollout.percent }) }}
              </dd>
            </div>
            <div v-if="latestPublished">
              <dt>{{ t('overview.updates.latestPublished') }}</dt>
              <dd class="mono pd-tabular">
                {{ latestPublished }}
              </dd>
            </div>
            <div>
              <dt>{{ t('overview.updates.osReleases') }}</dt>
              <dd class="mono pd-tabular">
                <span
                  v-for="r in overview.updates.os_releases"
                  :key="r.release"
                  class="pd-block"
                >{{ t('overview.updates.osRelease', { release: r.release === 'unknown' ? t('overview.updates.unknownRelease') : r.release, count: r.devices }) }}</span>
                <span
                  v-if="overview.updates.os_releases.length === 0"
                  class="pd-muted"
                >–</span>
              </dd>
            </div>
          </dl>
        </section>

        <section
          v-if="session.canReadAudit"
          class="pd-panel pd-overview-audit"
          data-testid="overview-audit"
          aria-labelledby="overview-audit-title"
        >
          <header class="pd-panel-header">
            <h2
              id="overview-audit-title"
              class="pd-type-section"
            >
              {{ t('overview.audit.title') }}
            </h2>
            <RouterLink
              :to="{ name: 'audit' }"
              class="pd-panel-link"
            >
              {{ t('overview.audit.open') }}
              <kbd
                class="pd-kbd"
                aria-hidden="true"
              >{{ shortcutOf('/audit') }}</kbd>
            </RouterLink>
          </header>
          <p
            v-if="audit.length === 0"
            class="pd-panel-body pd-muted"
          >
            {{ t('overview.audit.empty') }}
          </p>
          <div
            v-else
            class="pd-table-scroll"
          >
            <table class="pd-table">
              <thead>
                <tr>
                  <th scope="col">
                    {{ t('audit.time') }}
                  </th>
                  <th
                    scope="col"
                    class="pd-hide-sm"
                  >
                    {{ t('audit.actor') }}
                  </th>
                  <th scope="col">
                    {{ t('audit.event') }}
                  </th>
                  <th
                    scope="col"
                    class="pd-hide-md"
                  >
                    {{ t('overview.audit.code') }}
                  </th>
                  <th scope="col">
                    {{ t('audit.outcome') }}
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="e in audit"
                  :key="e.event_id"
                >
                  <td>
                    <TimeCell
                      :iso="e.occurred_at"
                      precision="second"
                    />
                  </td>
                  <td class="pd-hide-sm">
                    <ActorChip :actor="e.actor" />
                  </td>
                  <td>{{ auditText(t, te, e) }}</td>
                  <td class="pd-hide-md mono">
                    {{ e.code }}
                  </td>
                  <td>
                    <StatusChip
                      :status="outcomeStatus(e.outcome).status"
                      :label="t(outcomeStatus(e.outcome).label)"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
      <p class="pd-type-caption pd-muted pd-overview-hint">
        {{ t('overview.keyboardHint', { mod: modifierLabel() }) }}
      </p>
    </template>
  </section>
</template>
