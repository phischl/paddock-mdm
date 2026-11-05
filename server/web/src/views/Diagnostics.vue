<script setup lang="ts">
// Every diagnostics bundle of the organization (ADR 0048, plan M12 decision 14); bundles are requested on a device.
import { useI18n } from 'vue-i18n'
import DiagnosticsList from '../components/DiagnosticsList.vue'
import { listDiagnostics } from '../lib/diagnostics'

const { t } = useI18n()
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('diagnostics.title') }}</h1>
    </div>
    <p class="summary">
      {{ t('diagnostics.fleetSummary') }}
    </p>
    <DiagnosticsList
      :fetch="listDiagnostics"
      fleet
    />
  </section>
</template>
