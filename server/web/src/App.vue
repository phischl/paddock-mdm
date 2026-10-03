<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useSessionStore } from './stores/session'
import ConfirmDialog from './components/ConfirmDialog.vue'
import { pendingConfirm, settleConfirm } from './composables/useConfirm'

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const showChrome = computed(() => !route.meta.public && session.me !== null)
const roleLabel = computed(() => (session.me ? t('roles.' + session.me.role) : ''))
</script>

<template>
  <v-app>
    <a
      class="skip-link"
      href="#main"
    >{{ t('app.skipToContent') }}</a>
    <v-app-bar
      v-if="showChrome"
      color="primary"
      flat
    >
      <v-app-bar-title class="brand">
        {{ t('app.name') }}
      </v-app-bar-title>
      <nav
        class="main-nav"
        :aria-label="t('app.mainNavigation')"
      >
        <v-btn
          v-if="session.canReadGroups"
          to="/device-groups"
          variant="text"
        >
          {{ t('nav.deviceGroups') }}
        </v-btn>
        <v-btn
          v-if="session.canReadAudit"
          to="/audit"
          variant="text"
        >
          {{ t('nav.audit') }}
        </v-btn>
        <v-btn
          v-if="session.isPlatform"
          to="/platform/organizations"
          variant="text"
        >
          {{ t('nav.organizations') }}
        </v-btn>
      </nav>
      <div class="user">
        <span data-testid="user-name">{{ t('app.signedInAs', { name: session.me?.display_name ?? '' }) }}</span>
        <span
          class="role"
          data-testid="user-role"
        >{{ roleLabel }}</span>
        <v-btn
          color="surface"
          @click="session.logout()"
        >
          {{ t('app.logout') }}
        </v-btn>
      </div>
    </v-app-bar>
    <v-main id="main">
      <RouterView />
    </v-main>
    <ConfirmDialog
      v-if="pendingConfirm"
      :model-value="true"
      v-bind="pendingConfirm.options"
      @confirm="settleConfirm(true)"
      @cancel="settleConfirm(false)"
    />
  </v-app>
</template>
