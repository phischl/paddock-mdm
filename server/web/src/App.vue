<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useTheme } from 'vuetify'
import { useSessionStore } from './stores/session'
import ConfirmDialog from './components/ConfirmDialog.vue'
import { pendingConfirm, settleConfirm } from './composables/useConfirm'
import { attentionCount } from './lib/updates'

const { t } = useI18n()
const route = useRoute()
const session = useSessionStore()
const showChrome = computed(() => !route.meta.public && session.me !== null)
const roleLabel = computed(() => (session.me ? t('roles.' + session.me.role) : ''))
// The symbol variant follows the theme (plan M4c step 0b); the files are copied from docs/assets/logo/ at build time.
const theme = useTheme()
const logo = computed(() => (theme.current.value.dark ? '/paddock-symbol-dark.svg' : '/paddock-symbol-light.svg'))

// The number of open conditions on the attention list, refreshed on every navigation (plan M5b decision 11).
const attention = ref(0)
watch(
  () => [route.fullPath, session.canReadGroups] as const,
  async ([, canRead]) => {
    attention.value = canRead ? await attentionCount() : 0
  },
  { immediate: true },
)

// While a dialog is open the page behind it is inert, as aria-modal promises: no focus, no screen reader access.
// Vuetify teleports dialogs to the body, outside the elements made inert here.
const modalOpen = ref(false)
const observer = new MutationObserver(() => {
  modalOpen.value = document.querySelector('.v-dialog.v-overlay--active') !== null
})
onMounted(() => observer.observe(document.body, { subtree: true, childList: true, attributeFilter: ['class'] }))
onBeforeUnmount(() => observer.disconnect())
</script>

<template>
  <v-app>
    <a
      class="skip-link"
      :inert="modalOpen"
      href="#main"
    >{{ t('app.skipToContent') }}</a>
    <v-app-bar
      v-if="showChrome"
      :inert="modalOpen"
      color="primary"
      flat
    >
      <template #prepend>
        <img
          :src="logo"
          alt=""
          width="32"
          height="32"
          class="ms-2"
          data-testid="app-logo"
        >
      </template>
      <v-app-bar-title class="brand">
        {{ t('app.name') }}
      </v-app-bar-title>
      <nav
        class="main-nav"
        :aria-label="t('app.mainNavigation')"
      >
        <v-btn
          v-if="session.canReadGroups"
          to="/attention"
          variant="text"
          data-testid="nav-attention"
        >
          {{ t('nav.attention') }}
          <v-badge
            v-if="attention > 0"
            :content="attention"
            color="error"
            inline
            :aria-label="t('nav.attentionCount', { count: attention })"
            data-testid="attention-count"
          />
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/devices"
          variant="text"
        >
          {{ t('nav.devices') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/device-groups"
          variant="text"
        >
          {{ t('nav.deviceGroups') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/software"
          variant="text"
        >
          {{ t('nav.software') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/vulnerabilities"
          variant="text"
        >
          {{ t('nav.vulnerabilities') }}
        </v-btn>
        <v-btn
          v-if="session.canWrite"
          to="/enrollment-tokens"
          variant="text"
        >
          {{ t('nav.enrollmentTokens') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/managed-files"
          variant="text"
        >
          {{ t('nav.managedFiles') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/managed-units"
          variant="text"
        >
          {{ t('nav.managedUnits') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/package-holds"
          variant="text"
        >
          {{ t('nav.packageHolds') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/users"
          variant="text"
        >
          {{ t('nav.users') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/user-groups"
          variant="text"
        >
          {{ t('nav.userGroups') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/permission-profiles"
          variant="text"
        >
          {{ t('nav.permissionProfiles') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/settings/login"
          variant="text"
        >
          {{ t('nav.loginSettings') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/settings/updates"
          variant="text"
        >
          {{ t('nav.updateSettings') }}
        </v-btn>
        <v-btn
          v-if="session.canDelete"
          to="/revocations"
          variant="text"
        >
          {{ t('nav.revocations') }}
        </v-btn>
        <v-btn
          v-if="session.canReadGroups"
          to="/settings/dms"
          variant="text"
        >
          {{ t('nav.dms') }}
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
        <v-btn
          v-if="session.isPlatform"
          to="/platform/agent-releases"
          variant="text"
        >
          {{ t('nav.agentReleases') }}
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
    <v-main
      id="main"
      :inert="modalOpen"
    >
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
