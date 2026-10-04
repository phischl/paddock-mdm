<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { UserEffectiveProfile } from '../api/client'

/** An effective sudo profile with the assignment that granted each part (architecture §10.2). */
defineProps<{ profile: UserEffectiveProfile; subjectName: (type: string, id: string | null) => string }>()
const { t } = useI18n()
</script>

<template>
  <div data-testid="effective-profile">
    <v-alert
      v-if="profile.root_equivalent"
      type="warning"
      variant="tonal"
      class="conflict"
      data-testid="root-equivalent-warning"
    >
      {{ t('profiles.rootEquivalentEffective', { commands: profile.root_equivalent_commands.join(', ') }) }}
    </v-alert>
    <v-table class="table facts">
      <tbody>
        <tr>
          <th scope="row">
            {{ t('profiles.class') }}
          </th>
          <td data-testid="effective-class">
            {{ profile.reported_class === profile.class ? t('profiles.classes.' + profile.class)
              : t('profiles.classReported', { class: t('profiles.classes.' + profile.class), reported: t('profiles.classes.' + profile.reported_class) }) }}
          </td>
        </tr>
        <tr>
          <th scope="row">
            {{ t('profiles.commands') }}
          </th>
          <td>{{ profile.commands.join(', ') || '–' }}</td>
        </tr>
        <tr>
          <th scope="row">
            {{ t('profiles.scalars') }}
          </th>
          <td>
            {{ t('profiles.scalarFacts', { password: String(profile.require_password), timeout: profile.timestamp_timeout_min, lecture: t('profiles.lectures.' + profile.lecture) }) }}
          </td>
        </tr>
      </tbody>
    </v-table>
    <v-table
      class="table"
      data-testid="derivation"
    >
      <caption>{{ t('profiles.derivation') }}</caption>
      <thead>
        <tr>
          <th scope="col">
            {{ t('profiles.granted') }}
          </th>
          <th scope="col">
            {{ t('profiles.profile') }}
          </th>
          <th scope="col">
            {{ t('profiles.assignedTo') }}
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="profile.derivation.length === 0">
          <td colspan="3">
            {{ t('profiles.noAssignment') }}
          </td>
        </tr>
        <tr
          v-for="d in profile.derivation"
          :key="d.kind + d.item + d.assignment_id"
        >
          <td>{{ t('profiles.derived.' + d.kind, { item: d.item, value: d.value }) }}</td>
          <td>
            <RouterLink :to="{ name: 'permission-profile', params: { id: d.profile_id } }">
              {{ d.profile_name }}
            </RouterLink>
          </td>
          <td>{{ subjectName(d.subject.type, d.subject.id) }}</td>
        </tr>
      </tbody>
    </v-table>
  </div>
</template>
