<script setup lang="ts">
import { inject } from 'vue'
import { useI18n } from 'vue-i18n'
import { deviceDetailKey } from '../lib/deviceDetailPage'

/** The Configuration tab of a device (plan M7c decision 29): conflicts, effective managed files and units. */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceConfiguration outside the device frame')
const { config, groups } = page
const { t } = useI18n()

function groupName(id: string | null | undefined): string {
  if (!id) return t('managed.allDevices')
  return groups.value.find((g) => g.id === id)?.name ?? id
}
</script>

<template>
  <div class="pd-device-tab">
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
      <section
        class="pd-panel"
        aria-labelledby="effective-files-title"
      >
        <header class="pd-panel-header">
          <h2
            id="effective-files-title"
            class="pd-type-section"
          >
            {{ t('managed.files.title') }}
          </h2>
        </header>
        <v-table
          class="table"
          data-testid="effective-files"
        >
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
              <td
                colspan="3"
                class="pd-muted"
              >
                {{ t('common.empty') }}
              </td>
            </tr>
            <tr
              v-for="f in config.files"
              :key="f.id"
            >
              <td class="mono">
                {{ f.path }}
              </td>
              <td class="mono">
                {{ f.mode }} {{ f.owner }}:{{ f.group }}
              </td>
              <td>{{ groupName(f.device_group_id) }}</td>
            </tr>
          </tbody>
        </v-table>
      </section>
      <section
        class="pd-panel"
        aria-labelledby="effective-units-title"
      >
        <header class="pd-panel-header">
          <h2
            id="effective-units-title"
            class="pd-type-section"
          >
            {{ t('managed.units.title') }}
          </h2>
        </header>
        <v-table
          class="table"
          data-testid="effective-units"
        >
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
              <td
                colspan="3"
                class="pd-muted"
              >
                {{ t('common.empty') }}
              </td>
            </tr>
            <tr
              v-for="u in config.units"
              :key="u.id"
            >
              <td class="mono">
                {{ u.unit }}
              </td>
              <td>{{ t('managed.units.wantedState', { enabled: String(u.enabled), active: String(u.active) }) }}</td>
              <td>{{ groupName(u.device_group_id) }}</td>
            </tr>
          </tbody>
        </v-table>
      </section>
    </template>
  </div>
</template>
