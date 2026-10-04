<script setup lang="ts">
import { onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAgentReleasePage } from '../lib/agentReleasePage'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'

const { t, n, locale } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const { detail, problem, actions, load, run } = useAgentReleasePage(() => String(route.params.version))
onMounted(load)
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'agent-releases' }">
        {{ t('agentReleases.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="detail">
      <div class="page-header">
        <h1>{{ t('agentReleases.heading', { version: detail.release.version }) }}</h1>
        <div class="row-actions">
          <v-btn
            v-for="action in actions"
            :key="action"
            :color="action === 'halt' ? 'error' : 'primary'"
            :data-testid="'rollout-' + action"
            @click="run(action)"
          >
            {{ t('agentReleases.actions.' + action + '.label') }}
          </v-btn>
        </div>
      </div>

      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('agentReleases.status') }}
            </th>
            <td data-testid="release-status">
              {{ t('agentReleases.statuses.' + detail.release.status) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('agentReleases.createdBy') }}
            </th>
            <td>{{ t('agentReleases.createdFacts', { by: detail.release.created_by, at: formatDateTime(detail.release.created_at, locale) }) }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('agentReleases.publishedAt') }}
            </th>
            <td>{{ detail.release.published_at ? formatDateTime(detail.release.published_at, locale) : '–' }}</td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('agentReleases.artifacts') }}</h2>
      <v-table
        class="table"
        data-testid="release-artifacts"
      >
        <thead>
          <tr>
            <th>{{ t('agentReleases.arch') }}</th>
            <th>{{ t('agentReleases.sha256') }}</th>
            <th>{{ t('agentReleases.size') }}</th>
            <th>{{ t('agentReleases.uploadedAt') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="a in detail.artifacts"
            :key="a.arch"
          >
            <td>{{ a.arch }}</td>
            <td class="mono">
              {{ a.sha256 }}
            </td>
            <td>{{ t('agentReleases.bytes', { size: a.size }) }}</td>
            <td>{{ formatDateTime(a.created_at, locale) }}</td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('agentReleases.rollout') }}</h2>
      <p v-if="!detail.rollout">
        {{ t('agentReleases.noRollout') }}
      </p>
      <v-table
        v-else
        class="table facts"
        data-testid="release-rollout"
      >
        <tbody>
          <tr>
            <th scope="row">
              {{ t('agentReleases.rolloutStatus') }}
            </th>
            <td data-testid="rollout-status">
              {{ t('agentReleases.rolloutStatuses.' + detail.rollout.status) }}
            </td>
          </tr>
          <tr v-if="detail.rollout.halted_reason">
            <th scope="row">
              {{ t('agentReleases.haltedReason') }}
            </th>
            <td>{{ detail.rollout.halted_reason }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('agentReleases.wave') }}
            </th>
            <td data-testid="rollout-wave">
              {{ t('agentReleases.waveFacts', {
                wave: detail.rollout.current_wave_index + 1,
                waves: detail.rollout.waves.length,
                percent: n(detail.rollout.waves[detail.rollout.current_wave_index] ?? 0),
                since: formatDateTime(detail.rollout.wave_started_at, locale),
              }) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('agentReleases.waves') }}
            </th>
            <td>{{ detail.rollout.waves.map((w) => w + ' %').join(' → ') }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('agentReleases.thresholds') }}
            </th>
            <td>
              {{ t('agentReleases.thresholdFacts', {
                minutes: detail.rollout.min_wave_minutes,
                percent: detail.rollout.failure_threshold_percent,
                min: detail.rollout.failure_threshold_min,
              }) }}
            </td>
          </tr>
          <tr v-if="detail.counts">
            <th scope="row">
              {{ t('agentReleases.devices') }}
            </th>
            <td data-testid="rollout-counts">
              {{ t('agentReleases.countFacts', {
                eligible: detail.counts.eligible, updated: detail.counts.updated, failed: detail.counts.failed,
              }) }}
            </td>
          </tr>
        </tbody>
      </v-table>
    </template>
  </section>
</template>
