<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <section class="page narrow">
    <h1>{{ t('notFound.title') }}</h1>
    <RouterLink to="/">
      {{ t('notFound.back') }}
    </RouterLink>
  </section>
</template>
