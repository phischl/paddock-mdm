<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import { useSessionStore } from './stores/session'

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const showChrome = computed(() => !route.meta.public && session.me !== null)
const roleLabel = computed(() => (session.me ? t('roles.' + session.me.role) : ''))
</script>

<template>
  <a
    class="skip-link"
    href="#main"
  >{{ t('app.skipToContent') }}</a>
  <header
    v-if="showChrome"
    class="app-header"
  >
    <span class="brand">{{ t('app.name') }}</span>
    <nav
      class="main-nav"
      :aria-label="t('app.mainNavigation')"
    >
      <RouterLink
        v-if="session.canReadGroups"
        to="/device-groups"
      >
        {{ t('nav.deviceGroups') }}
      </RouterLink>
      <RouterLink
        v-if="session.canReadAudit"
        to="/audit"
      >
        {{ t('nav.audit') }}
      </RouterLink>
      <RouterLink
        v-if="session.isPlatform"
        to="/platform/organizations"
      >
        {{ t('nav.organizations') }}
      </RouterLink>
    </nav>
    <div class="user">
      <span data-testid="user-name">{{ t('app.signedInAs', { name: session.me?.display_name ?? '' }) }}</span>
      <span
        class="role"
        data-testid="user-role"
      >{{ roleLabel }}</span>
      <Button
        :label="t('app.logout')"
        severity="secondary"
        @click="session.logout()"
      />
    </div>
  </header>
  <main id="main">
    <RouterView />
  </main>
</template>
