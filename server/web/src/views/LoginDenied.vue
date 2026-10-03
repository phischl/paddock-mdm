<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

const { t, te } = useI18n()
const route = useRoute()
const message = computed(() => {
  const reason = typeof route.query.reason === 'string' ? route.query.reason : 'login_failed'
  return te('loginDenied.' + reason) ? t('loginDenied.' + reason) : t('loginDenied.login_failed')
})
</script>

<template>
  <section class="page narrow">
    <h1>{{ t('loginDenied.title') }}</h1>
    <p data-testid="login-denied-message">
      {{ message }}
    </p>
    <a
      class="link-button"
      href="/api/auth/login"
    >{{ t('loginDenied.retry') }}</a>
  </section>
</template>
