<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '../api/client'

const { t, te } = useI18n()
const route = useRoute()
const reason = computed(() => (typeof route.query.reason === 'string' ? route.query.reason : 'login_failed'))
const message = computed(() =>
  te('loginDenied.' + reason.value) ? t('loginDenied.' + reason.value) : t('loginDenied.login_failed'))
const signingOut = ref(false)

/**
 * Ends the identity provider's session, so that the next sign-in runs the login flow again instead of reusing the
 * session that was refused (ADR 0034 amendment 2026-10-29). The logout's end_session_url is Authentik's brand
 * invalidation flow, which ends that session (PDK-532).
 */
async function signOutOfIdentityProvider(): Promise<void> {
  signingOut.value = true
  let target = '/'
  try {
    const { data } = await api.POST('/api/auth/logout', { params: { header: { 'X-Paddock-CSRF': '1' } } })
    target = data?.end_session_url ?? '/'
  } catch {
    target = '/'
  }
  window.location.assign(target)
}
</script>

<template>
  <section class="page narrow">
    <h1>{{ t('loginDenied.title') }}</h1>
    <p data-testid="login-denied-message">
      {{ message }}
    </p>
    <button
      v-if="reason === 'passkey_required'"
      type="button"
      class="link-button"
      :disabled="signingOut"
      @click="signOutOfIdentityProvider"
    >
      {{ t('loginDenied.signOutIdentityProvider') }}
    </button>
    <a
      class="link-button"
      href="/api/auth/login"
    >{{ t('loginDenied.retry') }}</a>
  </section>
</template>
