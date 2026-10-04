<script setup lang="ts">
import { onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useDeviceDetailPage } from '../lib/deviceDetailPage'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const session = useSessionStore()
const { device, config, groups, selectedGroups, problem, saved, actions, load, run, saveGroups } =
  useDeviceDetailPage(() => String(route.params.id))
onMounted(load)

function groupName(id: string | null | undefined): string {
  if (!id) return t('managed.allDevices')
  return groups.value.find((g) => g.id === id)?.name ?? id
}
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'devices' }">
        {{ t('devices.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="device">
      <div class="page-header">
        <h1>{{ device.hostname }}</h1>
        <div class="row-actions">
          <v-btn
            v-for="action in actions"
            :key="action"
            :color="action === 'retire' || action === 'reject' ? 'error' : 'primary'"
            :data-testid="'device-' + action"
            @click="run(action)"
          >
            {{ t('devices.actions.' + action + '.label') }}
          </v-btn>
        </div>
      </div>

      <h2>{{ t('devices.identity') }}</h2>
      <v-table
        class="table facts"
        data-testid="device-identity"
      >
        <tbody>
          <tr>
            <th scope="row">
              {{ t('devices.state') }}
            </th>
            <td data-testid="device-state">
              {{ t('devices.states.' + device.state) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.id') }}
            </th>
            <td>{{ device.id }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.hardwareUuid') }}
            </th>
            <td>{{ device.hardware_uuid ?? '–' }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.osRelease') }}
            </th>
            <td>{{ Object.entries(device.os_release).map(([k, v]) => k + '=' + v).join(', ') || '–' }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.agentVersion') }}
            </th>
            <td>{{ device.agent_version ?? '–' }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.enrolledAt') }}
            </th>
            <td>{{ formatDateTime(device.enrolled_at, locale) }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.lastContact') }}
            </th>
            <td>{{ device.last_contact_at ? formatDateTime(device.last_contact_at, locale) : t('devices.never') }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('devices.bundleVersion') }}
            </th>
            <td>{{ t('devices.versions', { applied: device.applied_bundle_version ?? 0, latest: device.bundle_version }) }}</td>
          </tr>
          <tr
            v-for="key in device.identity_keys"
            :key="key.key_id"
          >
            <th scope="row">
              {{ t('devices.identityKey') }}
            </th>
            <td>
              {{ t('devices.keyFacts', { id: key.key_id.slice(0, 16), protection: key.key_protection, status: key.status }) }}
            </td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('devices.groups') }}</h2>
      <form
        class="form groups-form"
        novalidate
        @submit.prevent="saveGroups"
      >
        <v-autocomplete
          v-model="selectedGroups"
          :items="groups.map((g) => ({ value: g.id, title: g.name }))"
          :label="t('devices.groups')"
          :disabled="!session.canWrite"
          multiple
          chips
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
            color="primary"
            data-testid="save-device-groups"
          >
            {{ t('common.save') }}
          </v-btn>
        </div>
      </form>

      <h2>{{ t('devices.effectiveConfig') }}</h2>
      <template v-if="config">
        <v-alert
          v-for="c in config.conflicts"
          :key="c.resource"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="config-conflict"
        >
          {{ t('devices.conflict', { resource: c.resource, count: c.loser_ids.length }) }}
        </v-alert>
        <v-table
          class="table"
          data-testid="effective-files"
        >
          <caption>{{ t('managed.files.title') }}</caption>
          <thead>
            <tr>
              <th scope="col">
                {{ t('managed.files.path') }}
              </th>
              <th scope="col">
                {{ t('managed.files.mode') }}
              </th>
              <th scope="col">
                {{ t('managed.scope') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="config.files.length === 0">
              <td colspan="3">
                {{ t('common.empty') }}
              </td>
            </tr>
            <tr
              v-for="f in config.files"
              :key="f.id"
            >
              <td>{{ f.path }}</td>
              <td>{{ f.mode }} {{ f.owner }}:{{ f.group }}</td>
              <td>{{ groupName(f.device_group_id) }}</td>
            </tr>
          </tbody>
        </v-table>
        <v-table
          class="table"
          data-testid="effective-units"
        >
          <caption>{{ t('managed.units.title') }}</caption>
          <thead>
            <tr>
              <th scope="col">
                {{ t('managed.units.unit') }}
              </th>
              <th scope="col">
                {{ t('managed.units.wanted') }}
              </th>
              <th scope="col">
                {{ t('managed.scope') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="config.units.length === 0">
              <td colspan="3">
                {{ t('common.empty') }}
              </td>
            </tr>
            <tr
              v-for="u in config.units"
              :key="u.id"
            >
              <td>{{ u.unit }}</td>
              <td>{{ t('managed.units.wantedState', { enabled: String(u.enabled), active: String(u.active) }) }}</td>
              <td>{{ groupName(u.device_group_id) }}</td>
            </tr>
          </tbody>
        </v-table>
      </template>
    </template>
  </section>
</template>
