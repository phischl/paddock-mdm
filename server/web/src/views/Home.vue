<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <p class="page">
    {{ t('app.loading') }}
  </p>
</template>
