<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSessionStore } from '../stores/session'
import { formatDateTime } from '../lib/format'

/**
 * Warns an organization administrator while the deletion of the organization is pending (plan M17, OFB-5): the date
 * and what to secure before the data is gone. Not dismissible, the organization must not be surprised by it.
 */
const { t, locale } = useI18n()
const session = useSessionStore()
const deletion = computed(() => (session.me?.role === 'org_admin' ? session.me.organization_deletion : null))
</script>

<template>
  <v-alert
    v-if="deletion"
    type="warning"
    variant="tonal"
    rounded="0"
    data-testid="organization-deletion-banner"
  >
    <p>{{ t('organizations.banner.message', { date: formatDateTime(deletion.delete_after, locale) }) }}</p>
    <p>{{ t('organizations.banner.advice') }}</p>
  </v-alert>
</template>
