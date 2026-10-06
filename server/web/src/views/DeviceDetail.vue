<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import LocalAdminCard from '../components/LocalAdminCard.vue'
import DiskEncryptionCard from '../components/DiskEncryptionCard.vue'
import type { DeviceCommand } from '../api/client'
import { useDeviceDetailPage } from '../lib/deviceDetailPage'
import type { ListColumn } from '../lib/listQuery'
import { commandFilters, listCommands } from '../lib/localAdmin'
import { reportText } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const session = useSessionStore()
const {
  device, config, groups, selectedGroups, problem, saved, actions, load, run, saveGroups,
  users, userGroups, loginUsers, loginGroups, loginSaved, sudo, loadSubjects, saveLogin, toggleSuspension,
} = useDeviceDetailPage(() => String(route.params.id))
onMounted(async () => {
  await load()
  await loadSubjects()
})

const commandList = ref<{ reload: () => Promise<void> } | null>(null)
const fetchCommands = computed(() => listCommands(String(route.params.id)))
const commandColumns: ListColumn[] = [
  { key: 'type', title: 'commands.type', sortable: true },
  { key: 'status', title: 'commands.status', sortable: true },
  { key: 'issued_at', title: 'commands.issuedAt', sortable: true },
  { key: 'expires_at', title: 'commands.expiresAt', sortable: true },
]

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
          <tr>
            <th scope="row">
              {{ t('devices.sudoFlavor') }}
            </th>
            <td data-testid="device-sudo-flavor">
              {{ device.sudo_flavor ? t('devices.sudoFlavors.' + device.sudo_flavor) : '–' }}
            </td>
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

      <LocalAdminCard
        :device-id="device.id"
        :hostname="device.hostname"
        :active="device.state === 'active'"
        @changed="commandList?.reload()"
      />

      <DiskEncryptionCard
        :device-id="device.id"
        :hostname="device.hostname"
      />

      <h2>{{ t('commands.title') }}</h2>
      <DataList
        ref="commandList"
        :columns="commandColumns"
        :fetch="fetchCommands"
        :filters="commandFilters"
        default-sort="-issued_at"
        item-value="id"
        data-testid="command-list"
      >
        <template #[`item.type`]="{ item }: { item: DeviceCommand }">
          {{ t('commands.types.' + item.type) }}
        </template>
        <template #[`item.status`]="{ item }: { item: DeviceCommand }">
          {{ t('commands.statuses.' + item.status) }}
        </template>
        <template #[`item.issued_at`]="{ item }: { item: DeviceCommand }">
          {{ formatDateTime(item.issued_at, locale) }}
        </template>
        <template #[`item.expires_at`]="{ item }: { item: DeviceCommand }">
          {{ formatDateTime(item.expires_at, locale) }}
        </template>
      </DataList>

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

      <h2>{{ t('devices.login.title') }}</h2>
      <v-alert
        v-if="!device.login_management"
        type="info"
        variant="tonal"
        class="conflict"
        data-testid="agent-too-old"
      >
        {{ t('devices.login.agentTooOld') }}
      </v-alert>
      <v-alert
        v-if="device.logins_suspended"
        type="warning"
        variant="tonal"
        class="conflict"
        data-testid="logins-suspended"
      >
        {{ t('devices.login.suspendedHint') }}
      </v-alert>
      <form
        class="form groups-form"
        novalidate
        @submit.prevent="saveLogin"
      >
        <p class="summary">
          {{ t('devices.login.assignmentHint') }}
        </p>
        <v-autocomplete
          v-model="loginUsers"
          :items="session.canWrite ? users.map((u) => ({ value: u.id, title: u.username })) : device.login_assignment.users.map((u) => ({ value: u.id, title: u.username }))"
          :label="t('devices.login.users')"
          :disabled="!session.canWrite"
          multiple
          chips
          data-testid="login-users"
        />
        <v-autocomplete
          v-model="loginGroups"
          :items="session.canWrite ? userGroups.map((g) => ({ value: g.id, title: g.name })) : device.login_assignment.groups.map((g) => ({ value: g.id, title: g.name }))"
          :label="t('devices.login.groups')"
          :disabled="!session.canWrite"
          multiple
          chips
          data-testid="login-groups"
        />
        <div
          v-if="session.canWrite"
          class="form-actions"
        >
          <span
            v-if="loginSaved"
            role="status"
          >{{ t('devices.login.saved') }}</span>
          <v-btn
            :color="device.logins_suspended ? 'primary' : 'error'"
            variant="outlined"
            data-testid="toggle-suspension"
            @click="toggleSuspension"
          >
            {{ t(device.logins_suspended ? 'devices.login.resume.label' : 'devices.login.suspend.label') }}
          </v-btn>
          <v-btn
            type="submit"
            color="primary"
            data-testid="save-login-assignment"
          >
            {{ t('common.save') }}
          </v-btn>
        </div>
      </form>

      <h2>{{ t('devices.sudo.title') }}</h2>
      <v-alert
        v-if="device.sudo_flavor === 'sudo-rs'"
        type="info"
        variant="tonal"
        class="conflict"
        data-testid="sudo-rs-lecture"
      >
        {{ t('devices.sudo.sudoRsLecture') }}
      </v-alert>
      <template v-if="sudo">
        <v-alert
          v-for="e in sudo.entries.filter((x) => x.root_equivalent)"
          :key="'root-' + e.user.id"
          type="warning"
          variant="tonal"
          class="conflict"
          data-testid="sudo-root-equivalent"
        >
          {{ t('devices.sudo.rootEquivalent', { username: e.user.username, commands: e.root_equivalent_commands.join(', ') }) }}
        </v-alert>
        <v-table
          class="table"
          data-testid="effective-sudo"
        >
          <caption>{{ t('devices.sudo.caption') }}</caption>
          <thead>
            <tr>
              <th scope="col">
                {{ t('users.username') }}
              </th>
              <th scope="col">
                {{ t('profiles.class') }}
              </th>
              <th scope="col">
                {{ t('profiles.commands') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="sudo.entries.length === 0">
              <td colspan="3">
                {{ t('devices.sudo.none') }}
              </td>
            </tr>
            <tr
              v-for="e in sudo.entries"
              :key="e.user.id"
            >
              <td>
                <RouterLink :to="{ name: 'user', params: { id: e.user.id } }">
                  {{ e.user.username }}
                </RouterLink>
              </td>
              <td>{{ t('profiles.classes.' + e.reported_class) }}</td>
              <td>{{ e.class === 'full' ? t('profiles.allCommands') : e.commands.join(', ') }}</td>
            </tr>
          </tbody>
        </v-table>
      </template>

      <h2>{{ t('devices.report.title') }}</h2>
      <v-table
        class="table"
        data-testid="device-reports"
      >
        <caption>{{ t('devices.report.caption') }}</caption>
        <thead>
          <tr>
            <th scope="col">
              {{ t('devices.report.area') }}
            </th>
            <th scope="col">
              {{ t('devices.report.report') }}
            </th>
            <th scope="col">
              {{ t('devices.report.at') }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="area in (['login', 'sudo'] as const)"
            :key="area"
            :data-testid="'device-report-' + area"
          >
            <th scope="row">
              {{ t('devices.report.areas.' + area) }}
            </th>
            <td>{{ device.login_status[area] ? reportText(t, device.login_status[area]) : t('devices.report.none') }}</td>
            <td>{{ device.login_status[area] ? formatDateTime(device.login_status[area].occurred_at, locale) : '–' }}</td>
          </tr>
        </tbody>
      </v-table>

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
