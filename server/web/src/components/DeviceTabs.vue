<script setup lang="ts">
import { useI18n } from 'vue-i18n'

/** The tabs of a device: details, installed software and vulnerabilities (plan M5a decision 10). */
defineProps<{ deviceId: string }>()
const { t } = useI18n()
</script>

<template>
  <v-tabs
    class="mb-4"
    color="primary"
    :aria-label="t('inventory.deviceTabs')"
  >
    <v-tab :to="{ name: 'device', params: { id: deviceId } }">
      {{ t('inventory.tabs.details') }}
    </v-tab>
    <v-tab
      :to="{ name: 'device-software', params: { id: deviceId } }"
      data-testid="tab-software"
    >
      {{ t('inventory.tabs.software') }}
    </v-tab>
    <v-tab
      :to="{ name: 'device-vulnerabilities', params: { id: deviceId } }"
      data-testid="tab-vulnerabilities"
    >
      {{ t('inventory.tabs.vulnerabilities') }}
    </v-tab>
  </v-tabs>
</template>
