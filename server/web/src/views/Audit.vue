<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import AuditEventList from '../components/AuditEventList.vue'
import { listAuditEvents } from '../lib/audit'

const { t } = useI18n()
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('audit.title') }}</h1>
      <v-btn
        :to="{ name: 'audit-exports' }"
        variant="tonal"
        data-testid="audit-exports-link"
      >
        {{ t('auditExports.title') }}
      </v-btn>
    </div>
    <AuditEventList
      :fetch="listAuditEvents"
      data-testid="audit-table"
    />
  </section>
</template>
