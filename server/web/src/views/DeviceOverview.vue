<script setup lang="ts">
import { computed, inject, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { VulnerabilityFinding } from '../api/client'
import DangerZone from '../components/DangerZone.vue'
import DeviceOwners from '../components/DeviceOwners.vue'
import DiskEncryptionCard from '../components/DiskEncryptionCard.vue'
import LocalAdminCard from '../components/LocalAdminCard.vue'
import SeverityChip from '../components/SeverityChip.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import UpdatesCard from '../components/UpdatesCard.vue'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import { healthRows } from '../lib/deviceHealth'
import { formatDateTime, formatGB, formatGiB } from '../lib/format'
import { listDeviceVulnerabilities } from '../lib/inventory'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/**
 * The Overview tab of a device (plan M7c decision 29): health and compliance, disk encryption and updates on the
 * left; identity, device groups and the local administrator on the right; the top findings; the danger zone last.
 */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceOverview outside the device frame')
const { device, groups, selectedGroups, saved, diskState, updates, conditions, refresh, saveGroups } = page
const { t, locale } = useI18n()
const { pending, run } = usePending()
const session = useSessionStore()
const findings = ref<VulnerabilityFinding[]>([])
const findingCount = ref(0)
const copied = ref(false)

const d = computed(() => device.value!)
/** The hardware rows of the identity panel (plan M8d decision 9): '–' while the inventory reports nothing. */
const hardwareRows = computed(() => {
  const hw = d.value.hardware
  const cpu = hw?.cpu_brand
    ? hw.cpu_brand + (hw.cpu_cores ? ' (' + t('devices.hardware.cpuCores', { cores: hw.cpu_cores }) + ')' : '')
    : null
  return [
    { key: 'manufacturer', value: hw?.vendor || null, mono: false },
    { key: 'model', value: hw?.model || null, mono: false },
    { key: 'serial', value: hw?.serial || null, mono: true },
    { key: 'cpu', value: cpu, mono: false },
    { key: 'memory', value: hw ? formatGiB(hw.memory_bytes, locale.value) : null, mono: false },
    { key: 'disk', value: hw ? formatGB(hw.disk_total_bytes, locale.value) : null, mono: false },
  ]
})
const health = computed(() =>
  healthRows({ device: d.value, diskState: diskState.value, updates: updates.value, conditions: conditions.value }),
)

onMounted(async () => {
  const res = await listDeviceVulnerabilities(d.value.id)({ page: 1, page_size: 10, sort: '-severity' }).catch(() => null)
  findings.value = res?.items.slice(0, 3) ?? []
  findingCount.value = res?.total ?? 0
})

async function copyId(): Promise<void> {
  await navigator.clipboard.writeText(d.value.id)
  copied.value = true
}
</script>

<template>
  <div class="pd-device-overview">
    <div class="pd-device-col">
      <section
        class="pd-panel"
        data-testid="device-health"
        aria-labelledby="device-health-title"
      >
        <header class="pd-panel-header">
          <h2
            id="device-health-title"
            class="pd-type-section"
          >
            {{ t('devices.health.title') }}
          </h2>
        </header>
        <ul class="pd-health">
          <li
            v-for="row in health"
            :key="row.key"
            :data-testid="'health-' + row.key"
          >
            <span class="pd-health-label">{{ t(row.label) }}</span>
            <StatusChip
              :status="row.view.status"
              :label="t(row.view.label)"
            />
          </li>
        </ul>
      </section>
      <DiskEncryptionCard
        :device-id="d.id"
        :hostname="d.hostname"
      />
      <UpdatesCard
        :device-id="d.id"
        :refresh="refresh"
      />
    </div>

    <div class="pd-device-col">
      <section
        class="pd-panel"
        aria-labelledby="device-identity-title"
      >
        <header class="pd-panel-header">
          <h2
            id="device-identity-title"
            class="pd-type-section"
          >
            {{ t('devices.identity') }}
          </h2>
        </header>
        <dl
          class="pd-panel-body pd-facts"
          data-testid="device-identity"
        >
          <div>
            <dt>{{ t('devices.state') }}</dt>
            <dd>{{ t('devices.states.' + d.state) }}</dd>
          </div>
          <div>
            <dt>{{ t('devices.id') }}</dt>
            <dd class="pd-identity-id">
              <span class="mono">{{ d.id }}</span>
              <v-btn
                size="x-small"
                variant="text"
                icon="pd:copy"
                :aria-label="t('devices.copyId')"
                @click="copyId"
              />
              <span
                v-if="copied"
                class="visually-hidden"
                role="status"
              >{{ t('devices.copied') }}</span>
            </dd>
          </div>
          <div>
            <dt>{{ t('devices.hardwareUuid') }}</dt>
            <dd :class="d.hardware_uuid ? 'mono' : 'pd-muted'">
              {{ d.hardware_uuid ?? '–' }}
            </dd>
          </div>
          <div
            v-for="row in hardwareRows"
            :key="row.key"
            :data-testid="'hardware-' + row.key"
          >
            <dt>{{ t('devices.hardware.' + row.key) }}</dt>
            <dd
              v-if="row.value"
              :class="row.mono ? 'mono' : ''"
            >
              {{ row.value }}
            </dd>
            <dd
              v-else
              class="pd-muted"
              :title="t('devices.hardware.pending')"
            >
              –
            </dd>
          </div>
          <div>
            <dt>{{ t('devices.osRelease') }}</dt>
            <dd>{{ d.os_release.PRETTY_NAME ?? (Object.entries(d.os_release).map(([k, v]) => k + '=' + v).join(', ') || '–') }}</dd>
          </div>
          <div>
            <dt>{{ t('devices.agentVersion') }}</dt>
            <dd :class="d.agent_version ? 'mono' : 'pd-muted'">
              {{ d.agent_version ?? '–' }}
            </dd>
          </div>
          <div>
            <dt>{{ t('devices.enrolledAt') }}</dt>
            <dd><TimeCell :iso="d.enrolled_at" /></dd>
          </div>
          <div>
            <dt>{{ t('devices.lastContact') }}</dt>
            <dd>
              <TimeCell
                v-if="d.last_contact_at"
                :iso="d.last_contact_at"
              />
              <span
                v-else
                class="pd-muted"
                :title="t('devices.noReportYet')"
              >{{ t('time.never') }}</span>
              <span
                v-if="d.presumed_lost_at"
                class="pd-block pd-type-caption"
                data-testid="device-presumed-lost"
              >{{ t('devices.presumedLost', { at: formatDateTime(d.presumed_lost_at, locale) }) }}</span>
            </dd>
          </div>
          <div>
            <dt>{{ t('devices.bundleVersion') }}</dt>
            <dd
              v-if="d.applied_bundle_version === null"
              class="pd-muted"
              :title="t('devices.noReportYet')"
            >
              {{ t('devices.versions', { applied: 0, latest: d.bundle_version }) }}
            </dd>
            <dd
              v-else
              class="mono"
            >
              {{ t('devices.versions', { applied: d.applied_bundle_version, latest: d.bundle_version }) }}
            </dd>
          </div>
          <div>
            <dt>{{ t('devices.sudoFlavor') }}</dt>
            <dd data-testid="device-sudo-flavor">
              {{ d.sudo_flavor ? t('devices.sudoFlavors.' + d.sudo_flavor) : '–' }}
            </dd>
          </div>
          <div
            v-for="key in d.identity_keys"
            :key="key.key_id"
          >
            <dt>{{ t('devices.identityKey') }}</dt>
            <dd class="mono">
              {{ t('devices.keyFacts', { id: key.key_id.slice(0, 16), protection: key.key_protection, status: key.status }) }}
            </dd>
          </div>
        </dl>
      </section>

      <DeviceOwners
        :device-id="d.id"
        :owners="d.owners"
        :can-write="session.canWrite"
        @saved="page.load()"
      />

      <section
        class="pd-panel"
        aria-labelledby="device-groups-title"
      >
        <header class="pd-panel-header">
          <h2
            id="device-groups-title"
            class="pd-type-section"
          >
            {{ t('devices.groups') }}
          </h2>
        </header>
        <form
          class="form pd-panel-body"
          novalidate
          @submit.prevent="run(saveGroups)"
        >
          <v-autocomplete
            v-model="selectedGroups"
            :items="groups.map((g) => ({ value: g.id, title: g.name }))"
            :label="t('devices.groups')"
            :disabled="!session.canWrite"
            multiple
            chips
            class="pd-chip-field"
            data-testid="device-groups"
          />
          <div
            v-if="session.canWrite"
            class="form-actions"
          >
            <span
              v-if="saved"
              role="status"
            >{{ t('devices.groupsSaved') }}</span>
            <v-btn
              type="submit"
              :loading="pending"
              :disabled="pending"
              color="primary"
              data-testid="save-device-groups"
            >
              {{ t('common.save') }}
            </v-btn>
          </div>
        </form>
      </section>

      <LocalAdminCard
        :device-id="d.id"
        :hostname="d.hostname"
        :refresh="refresh"
        @changed="page.changed()"
      />
    </div>

    <section
      class="pd-panel pd-device-wide"
      data-testid="device-findings"
      aria-labelledby="device-findings-title"
    >
      <header class="pd-panel-header">
        <h2
          id="device-findings-title"
          class="pd-type-section"
        >
          {{ t('devices.findings.title') }}
        </h2>
        <RouterLink
          v-if="findingCount > 0"
          :to="{ name: 'device-vulnerabilities', params: { id: d.id } }"
          class="pd-panel-link"
        >
          {{ t('devices.findings.all', { count: findingCount }) }}
        </RouterLink>
      </header>
      <p
        v-if="findings.length === 0"
        class="pd-panel-body pd-muted"
      >
        {{ t('inventory.empty.deviceVulnerabilities.title') }}
      </p>
      <ul
        v-else
        class="pd-panel-body pd-top-cves"
      >
        <li
          v-for="f in findings"
          :key="f.cve + f.software_name"
        >
          <span class="pd-top-cve-id">
            <RouterLink
              :to="{ name: 'vulnerability', params: { cve: f.cve } }"
              class="mono"
            >{{ f.cve }}</RouterLink>
            <span class="pd-type-caption pd-muted mono">{{ f.software_name }} {{ f.software_version }}</span>
          </span>
          <SeverityChip :severity="f.severity" />
        </li>
      </ul>
    </section>

    <DangerZone
      class="pd-device-wide"
      :device-id="d.id"
      :hostname="d.hostname"
      :revocable="d.state === 'active' || d.state === 'quarantined'"
      :presumed-self-locked-at="d.presumed_self_locked_at"
      :retirable="page.actions.value.includes('retire')"
      :uninstallable="d.state === 'active'"
      :uninstall="d.uninstall ?? null"
      :disk-tpm="page.diskTpm.value"
      @retire="page.run('retire')"
      @changed="page.changed()"
    />
  </div>
</template>
