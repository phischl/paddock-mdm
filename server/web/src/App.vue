<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useDisplay, useTheme } from 'vuetify'
import { useSessionStore } from './stores/session'
import ConfirmDialog from './components/ConfirmDialog.vue'
import { pendingConfirm, settleConfirm } from './composables/useConfirm'
import { attentionCount } from './lib/updates'
import { visibleNavigation } from './lib/navigation'
import { navigationBreakpoint } from './plugins/vuetify'
import { portalLocales, type PortalLocale } from './i18n'

const { t, locale } = useI18n()
const route = useRoute()
const session = useSessionStore()
const showChrome = computed(() => !route.meta.public && session.me !== null)
const roleLabel = computed(() => (session.me ? t('roles.' + session.me.role) : ''))
const initial = computed(() => (session.me?.display_name ?? '').charAt(0).toUpperCase())
const groups = computed(() => visibleNavigation(session))
// The symbol variant follows the theme (plan M4c step 0b); the files are copied from docs/assets/logo/ at build time.
const theme = useTheme()
const logo = computed(() => (theme.current.value.dark ? '/paddock-symbol-dark.svg' : '/paddock-symbol-light.svg'))

// The drawer is permanent on wide screens, where the app bar button hides and shows it; below the breakpoint it is
// temporary and closes on every entry chosen, the current page included, so the page is not left covered.
const display = useDisplay()
const desktop = computed(() => display.width.value >= navigationBreakpoint)

// Hiding the drawer on wide screens is a per-viewer convenience: storage may be unavailable (private window, blocked
// site data), then the drawer starts shown. The key keeps its first name, so a stored choice stays readable.
const hiddenKey = 'paddock.navigation.rail'
function storedHidden(): boolean {
  try {
    return localStorage.getItem(hiddenKey) === 'true'
  } catch {
    return false
  }
}
const drawerOpen = ref(desktop.value && !storedHidden())
watch(desktop, (wide) => {
  drawerOpen.value = wide && !storedHidden()
})
function toggleDrawer(): void {
  drawerOpen.value = !drawerOpen.value
  if (!desktop.value) return
  try {
    localStorage.setItem(hiddenKey, String(!drawerOpen.value))
  } catch {
    // Not persisted; the choice holds until the page is reloaded.
  }
}
function closeOnSmallScreen(): void {
  if (!desktop.value) drawerOpen.value = false
}

// The number of open conditions on the attention list, refreshed on every navigation (plan M5b decision 11).
const attention = ref(0)
watch(
  () => [route.fullPath, session.canReadGroups] as const,
  async ([, canRead]) => {
    attention.value = canRead ? await attentionCount() : 0
  },
  { immediate: true },
)

// The language switch of the user menu stores the choice on the account (plan M6b decision 2).
const languageFailed = ref(false)
async function chooseLanguage(next: PortalLocale): Promise<void> {
  if (next === locale.value) return
  languageFailed.value = !(await session.setLocale(next))
}

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
        <v-app-bar-nav-icon
          :aria-label="drawerOpen ? t('app.hideNavigation') : t('app.showNavigation')"
          :aria-expanded="drawerOpen ? 'true' : 'false'"
          aria-controls="main-navigation"
          data-testid="nav-toggle"
          @click="toggleDrawer"
        />
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
        <span class="app-name">{{ t('app.name') }}</span>
        <span
          v-if="session.me?.organization"
          class="org-name"
          data-testid="org-name"
        >{{ session.me.organization.name }}</span>
      </v-app-bar-title>
      <template #append>
        <v-btn
          v-if="session.canReadGroups && attention > 0"
          to="/attention"
          variant="text"
          :aria-label="t('nav.attentionCount', { count: attention })"
          data-testid="app-bar-attention"
        >
          <v-badge
            :content="attention"
            color="error"
            inline
            aria-hidden="true"
            aria-live="off"
          />
        </v-btn>
        <v-menu>
          <template #activator="{ props: menu }">
            <v-btn
              v-bind="menu"
              variant="text"
              class="user-button"
              :aria-label="t('app.userMenu', { name: session.me?.display_name ?? '' })"
              data-testid="user-menu"
            >
              <v-avatar
                color="surface"
                size="28"
                aria-hidden="true"
              >
                {{ initial }}
              </v-avatar>
              <span class="user-button-name">{{ session.me?.display_name }}</span>
            </v-btn>
          </template>
          <v-list
            :aria-label="t('app.userMenu', { name: session.me?.display_name ?? '' })"
            density="compact"
          >
            <!-- A border instead of a divider: a separator is not allowed among the items of a list. -->
            <v-list-item class="border-b">
              <v-list-item-title
                class="text-wrap"
                data-testid="user-name"
              >
                {{ t('app.signedInAs', { name: session.me?.display_name ?? '' }) }}
              </v-list-item-title>
              <v-list-item-subtitle data-testid="user-role">
                {{ roleLabel }}
              </v-list-item-subtitle>
            </v-list-item>
            <v-menu submenu>
              <template #activator="{ props: languageMenu }">
                <v-list-item
                  v-bind="languageMenu"
                  :aria-label="t('app.languageMenu', { language: t('app.languages.' + locale) })"
                  data-testid="language-menu"
                >
                  <v-list-item-title>{{ t('app.language') }}</v-list-item-title>
                  <v-list-item-subtitle>{{ t('app.languages.' + locale) }}</v-list-item-subtitle>
                </v-list-item>
              </template>
              <v-list
                :aria-label="t('app.language')"
                density="compact"
              >
                <v-list-item
                  v-for="l in portalLocales"
                  :key="l"
                  :active="l === locale"
                  :lang="l"
                  :data-testid="'language-' + l"
                  @click="chooseLanguage(l)"
                >
                  <v-list-item-title>{{ t('app.languages.' + l) }}</v-list-item-title>
                </v-list-item>
              </v-list>
            </v-menu>
            <v-list-item
              data-testid="logout"
              @click="session.logout()"
            >
              <v-list-item-title>{{ t('app.logout') }}</v-list-item-title>
            </v-list-item>
          </v-list>
        </v-menu>
      </template>
    </v-app-bar>
    <!-- Bound only while a dialog is open: an inert attribute here would override the one Vuetify sets on a closed
         drawer. -->
    <v-navigation-drawer
      v-if="showChrome"
      id="main-navigation"
      v-model="drawerOpen"
      v-bind="modalOpen ? { inert: true } : {}"
      :permanent="desktop"
      :temporary="!desktop"
      :aria-label="t('app.mainNavigation')"
      data-testid="nav-drawer"
    >
      <!-- Not a v-list: it takes the links out of the tab order (arrow keys only) and its list role would require list
           items around them. Plain links keep every page one Tab stop away, in order. -->
      <div class="nav-groups">
        <div
          v-for="group in groups"
          :key="group.key"
          role="group"
          :aria-labelledby="'nav-group-' + group.key"
          :data-testid="'nav-group-' + group.key"
        >
          <v-list-subheader :id="'nav-group-' + group.key">
            {{ t(group.label) }}
          </v-list-subheader>
          <v-list-item
            v-for="item in group.items"
            :key="item.to"
            :to="item.to"
            nav
            density="compact"
            :data-testid="item.testid"
            @click="closeOnSmallScreen"
          >
            <v-list-item-title>{{ t(item.label) }}</v-list-item-title>
            <template
              v-if="item.to === '/attention' && attention > 0"
              #append
            >
              <!-- Vuetify makes a badge a polite live region; this count changes on every navigation and is not news. -->
              <v-badge
                :content="attention"
                color="error"
                inline
                :aria-label="t('nav.attentionCount', { count: attention })"
                role="img"
                aria-live="off"
                data-testid="attention-count"
              />
            </template>
          </v-list-item>
        </div>
      </div>
    </v-navigation-drawer>
    <v-main
      id="main"
      :inert="modalOpen"
    >
      <RouterView />
    </v-main>
    <v-snackbar
      v-model="languageFailed"
      color="error"
    >
      {{ t('app.languageFailed') }}
    </v-snackbar>
    <ConfirmDialog
      v-if="pendingConfirm"
      :model-value="true"
      v-bind="pendingConfirm.options"
      @confirm="settleConfirm(true)"
      @cancel="settleConfirm(false)"
    />
  </v-app>
</template>
