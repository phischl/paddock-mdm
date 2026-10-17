<script setup lang="ts">
import { computed, inject } from 'vue'
import { useI18n } from 'vue-i18n'
import TimeCell from '../components/TimeCell.vue'
import { deviceDetailKey } from '../lib/deviceDetailPage'
import { reportText } from '../lib/devices'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/** The Login & sudo tab of a device (plan M7c decision 29): login assignment, effective sudo rights, latest reports. */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceAccess outside the device frame')
const { device, users, userGroups, loginUsers, loginGroups, loginSaved, sudo, saveLogin, toggleSuspension } = page
const { t } = useI18n()
const { pending, run } = usePending()
const session = useSessionStore()
const d = computed(() => device.value!)
</script>

<template>
  <div class="pd-device-tab">
    <section
      class="pd-panel"
      aria-labelledby="device-login-title"
    >
      <header class="pd-panel-header">
        <h2
          id="device-login-title"
          class="pd-type-section"
        >
          {{ t('devices.login.title') }}
        </h2>
      </header>
      <div class="pd-panel-body">
        <v-alert
          v-if="!d.login_management"
          type="info"
          variant="tonal"
          class="conflict"
          data-testid="agent-too-old"
        >
          {{ t('devices.login.agentTooOld') }}
        </v-alert>
        <v-alert
          v-if="d.logins_suspended"
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
          @submit.prevent="run(saveLogin)"
        >
          <p class="summary">
            {{ t('devices.login.assignmentHint') }}
          </p>
          <v-autocomplete
            v-model="loginUsers"
            :items="session.canWrite ? users.map((u) => ({ value: u.id, title: u.username })) : d.login_assignment.users.map((u) => ({ value: u.id, title: u.username }))"
            :label="t('devices.login.users')"
            :disabled="!session.canWrite"
            multiple
            chips
            class="pd-chip-field"
            data-testid="login-users"
          />
          <v-autocomplete
            v-model="loginGroups"
            :items="session.canWrite ? userGroups.map((g) => ({ value: g.id, title: g.name })) : d.login_assignment.groups.map((g) => ({ value: g.id, title: g.name }))"
            :label="t('devices.login.groups')"
            :disabled="!session.canWrite"
            multiple
            chips
            class="pd-chip-field"
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
              :color="d.logins_suspended ? 'primary' : 'error'"
              variant="outlined"
              data-testid="toggle-suspension"
              @click="toggleSuspension"
            >
              {{ t(d.logins_suspended ? 'devices.login.resume.label' : 'devices.login.suspend.label') }}
            </v-btn>
            <v-btn
              type="submit"
              :loading="pending"
              :disabled="pending"
              color="primary"
              data-testid="save-login-assignment"
            >
              {{ t('common.save') }}
            </v-btn>
          </div>
        </form>
      </div>
    </section>

    <section
      class="pd-panel"
      aria-labelledby="device-sudo-title"
    >
      <header class="pd-panel-header">
        <h2
          id="device-sudo-title"
          class="pd-type-section"
        >
          {{ t('devices.sudo.title') }}
        </h2>
      </header>
      <div class="pd-panel-body">
        <v-alert
          v-if="d.sudo_flavor === 'sudo-rs'"
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
                <td class="mono">
                  {{ e.class === 'full' ? t('profiles.allCommands') : e.commands.join(', ') }}
                </td>
              </tr>
            </tbody>
          </v-table>
        </template>
      </div>
    </section>

    <section
      class="pd-panel"
      aria-labelledby="device-reports-title"
    >
      <header class="pd-panel-header">
        <h2
          id="device-reports-title"
          class="pd-type-section"
        >
          {{ t('devices.report.title') }}
        </h2>
      </header>
      <v-table
        class="table"
        data-testid="device-reports"
      >
        <caption class="visually-hidden">
          {{ t('devices.report.caption') }}
        </caption>
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
            <td>{{ d.login_status[area] ? reportText(t, d.login_status[area]) : t('devices.report.none') }}</td>
            <td>
              <TimeCell
                v-if="d.login_status[area]"
                :iso="d.login_status[area].occurred_at"
              />
              <span
                v-else
                class="pd-muted"
              >–</span>
            </td>
          </tr>
        </tbody>
      </v-table>
    </section>
  </div>
</template>
