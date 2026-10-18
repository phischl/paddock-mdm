<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useDisplay, useTheme } from 'vuetify'
import { useSessionStore } from './stores/session'
import ConfirmDialog from './components/ConfirmDialog.vue'
import CommandPalette from './components/CommandPalette.vue'
import ShortcutHelpDialog from './components/ShortcutHelpDialog.vue'
import PdIcon from './components/PdIcon'
import { pendingConfirm, settleConfirm } from './composables/useConfirm'
import { modifierLabel, useShortcuts } from './composables/useShortcuts'
import { attentionCount } from './lib/updates'
import { formatTime } from './lib/format'
import { shortcutRoutes, visibleNavigation } from './lib/navigation'
import { fetchPaletteDevices, fetchPaletteGroups, type Density, type PaletteContext } from './lib/commands'
import { currentDevice } from './lib/pageContext'
import type { ThemePreference } from './lib/theme'
import { mobileBreakpoint, navigationBreakpoint } from './plugins/vuetify'
import { portalLocales, type PortalLocale } from './i18n'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const showChrome = computed(() => !route.meta.public && session.me !== null)
const roleLabel = computed(() => (session.me ? t('roles.' + session.me.role) : ''))
const initial = computed(() => (session.me?.display_name ?? '').charAt(0).toUpperCase())
const groups = computed(() => visibleNavigation(session))
// The symbol variant follows the theme (plan M4c step 0b); the files are copied from docs/assets/logo/ at build time.
const theme = useTheme()
const isDark = computed(() => theme.current.value.dark)
const logo = computed(() => (isDark.value ? '/paddock-symbol-dark.svg' : '/paddock-symbol-light.svg'))
const mod = modifierLabel()

// Step-up freshness (plan M8x decision 35): the end of the session's step-up window, hidden at its expiry by a 1 s
// ticker. The step-up callback is a full navigation, so a new step-up arrives with a fresh GET /api/v1/me.
const now = ref(Date.now())
let ticker: ReturnType<typeof setInterval> | undefined
onMounted(() => { ticker = setInterval(() => { now.value = Date.now() }, 1000) })
onBeforeUnmount(() => clearInterval(ticker))
const stepUpUntil = computed(() => {
  const iso = session.me?.step_up_valid_until
  if (!iso || Date.parse(iso) <= now.value) return null
  return formatTime(iso, locale.value)
})

// Drawer states (plan M7c decision 15): expanded by default from 1280 px, a rail by default between 600 and
// 1279 px, both collapsible; a temporary drawer below 600 px that closes on every entry chosen.
const display = useDisplay()
const wide = computed(() => display.width.value >= navigationBreakpoint)
const mobile = computed(() => display.width.value < mobileBreakpoint)

// Collapsing is a per-viewer convenience: storage may be unavailable (private window, blocked site data), then the
// drawer starts in the default of the viewport. The key of the hidden drawer before M7c is read once and removed.
const collapsedKey = 'paddock.navigation.collapsed'
const legacyHiddenKey = 'paddock.navigation.hidden'
function storedCollapsed(): boolean | null {
  try {
    const value = localStorage.getItem(collapsedKey)
    if (value === 'true' || value === 'false') return value === 'true'
    const legacy = localStorage.getItem(legacyHiddenKey)
    if (legacy !== null) {
      localStorage.removeItem(legacyHiddenKey)
      if (legacy === 'true') {
        localStorage.setItem(collapsedKey, 'true')
        return true
      }
    }
    return null
  } catch {
    return null
  }
}
const collapsed = ref(storedCollapsed() ?? !wide.value)
const drawerOpen = ref(!mobile.value)
watch([wide, mobile], () => {
  collapsed.value = storedCollapsed() ?? !wide.value
  drawerOpen.value = !mobile.value
})
const rail = computed(() => !mobile.value && collapsed.value)
const navExpanded = computed(() => (mobile.value ? drawerOpen.value : !collapsed.value))
const navToggleLabel = computed(() => {
  if (wide.value) return t(collapsed.value ? 'app.expandNavigation' : 'app.collapseNavigation')
  return t(navExpanded.value ? 'app.hideNavigation' : 'app.showNavigation')
})
function toggleNav(): void {
  if (mobile.value) {
    drawerOpen.value = !drawerOpen.value
    return
  }
  collapsed.value = !collapsed.value
  try {
    localStorage.setItem(collapsedKey, String(collapsed.value))
  } catch {
    // Not persisted; the choice holds until the page is reloaded.
  }
}
function closeOnSmallScreen(): void {
  if (mobile.value) drawerOpen.value = false
}

// Roving tabindex in the drawer: one Tab stop (the current page's entry, else the first); Up/Down move, Home/End
// jump, Enter follows the link.
const nav = ref<HTMLElement | null>(null)
const navItems = computed(() => groups.value.flatMap((g) => g.items))
const focusedPath = ref<string | null>(null)
const tabStop = computed(() => {
  const paths = navItems.value.map((i) => i.to)
  if (focusedPath.value && paths.includes(focusedPath.value)) return focusedPath.value
  const current = paths.find((p) => (p === '/' ? route.path === '/' : route.path === p || route.path.startsWith(p + '/')))
  return current ?? paths[0] ?? null
})
function navLinks(): HTMLElement[] {
  return [...(nav.value?.querySelectorAll<HTMLElement>('a.pd-nav-item') ?? [])]
}
function onNavKeydown(e: KeyboardEvent): void {
  const links = navLinks()
  const index = links.findIndex((l) => l === document.activeElement)
  if (index < 0 || links.length === 0) return
  let next: number | null = null
  if (e.key === 'ArrowDown') next = (index + 1) % links.length
  else if (e.key === 'ArrowUp') next = (index - 1 + links.length) % links.length
  else if (e.key === 'Home') next = 0
  else if (e.key === 'End') next = links.length - 1
  if (next === null) return
  e.preventDefault()
  focusedPath.value = links[next].getAttribute('href')
  links[next].focus()
}

// The number of open conditions, shown as the attention pill and refreshed on every navigation (plan M5b decision 11).
const attention = ref(0)
watch(
  () => [route.fullPath, session.canReadGroups] as const,
  async ([, canRead]) => {
    attention.value = canRead ? await attentionCount() : 0
  },
  { immediate: true },
)

// The language, theme and density switches of the user menu; language and theme are stored on the account.
const languageFailed = ref(false)
const themeFailed = ref(false)
async function chooseLanguage(next: PortalLocale): Promise<void> {
  if (next === locale.value) return
  languageFailed.value = !(await session.setLocale(next))
}
async function chooseTheme(next: ThemePreference): Promise<void> {
  if (next === session.me?.theme) return
  themeFailed.value = !(await session.setTheme(next))
}
const densityKey = 'paddock.density'
function storedDensity(): Density {
  try {
    return localStorage.getItem(densityKey) === 'comfortable' ? 'comfortable' : 'compact'
  } catch {
    return 'compact'
  }
}
const density = ref<Density>(storedDensity())
function chooseDensity(next: Density): void {
  density.value = next
  try {
    localStorage.setItem(densityKey, next)
  } catch {
    // Not persisted; the choice holds until the page is reloaded.
  }
}
watch(density, (d) => (document.documentElement.dataset.density = d), { immediate: true })
const densityDefaults = computed(() => {
  const d = { density: density.value }
  return { VBtn: d, VTextField: d, VSelect: d, VTextarea: d, VAutocomplete: d, VDataTableServer: d, VListItem: d }
})

// The command palette and the shortcut help (plan M7c decisions 16–18).
const paletteOpen = ref(false)
const helpOpen = ref(false)
let ignoreFieldFocusUntil = 0
function openPalette(): void {
  paletteOpen.value = true
}
function onFieldFocus(e: FocusEvent): void {
  // Vuetify returns the focus to the field when the palette closes; that must not reopen it.
  if (Date.now() < ignoreFieldFocusUntil) {
    ;(e.target as HTMLElement).blur()
    return
  }
  openPalette()
}
watch(paletteOpen, (open) => {
  if (!open) ignoreFieldFocusUntil = Date.now() + 500
})
/** Opens the device's Overview tab when another tab is open and focuses the danger zone heading once it renders. */
async function goDangerZone(): Promise<void> {
  const device = currentDevice.value
  if (!device) return
  if (route.name !== 'device') await router.push({ name: 'device', params: { id: device.id }, query: route.query })
  for (let i = 0; i < 40; i++) {
    const heading = document.querySelector<HTMLElement>('#danger-zone h2')
    if (heading) {
      heading.scrollIntoView({ block: 'start' })
      heading.focus()
      return
    }
    await new Promise((r) => setTimeout(r, 50))
  }
}
const paletteContext = computed<PaletteContext>(() => ({
  pages: navItems.value.map((i) => ({ to: i.to, label: t(i.label), shortcut: i.shortcut })),
  canReadDevices: session.canReadGroups,
  preference: session.me?.theme ?? 'system',
  resolvedTheme: isDark.value ? 'dark' : 'light',
  locale: locale.value as PortalLocale,
  navCollapsed: !navExpanded.value,
  density: density.value,
  deviceHostname: currentDevice.value?.hostname,
  t: (key, values) => t(key, values ?? {}),
  go: (to) => void router.push(to),
  setTheme: (pref) => void chooseTheme(pref),
  setLocale: (l) => void chooseLanguage(l),
  toggleNav,
  openHelp: () => (helpOpen.value = true),
  setDensity: chooseDensity,
  goDangerZone: () => void goDangerZone(),
  fetchDevices: fetchPaletteDevices,
  fetchGroups: fetchPaletteGroups,
}))
useShortcuts({
  openPalette,
  openHelp: () => (helpOpen.value = true),
  toggleNav,
  go: (key) => {
    const to = shortcutRoutes(groups.value)[key]
    if (to) void router.push(to)
  },
  list: (action) => window.dispatchEvent(new CustomEvent('paddock:list', { detail: action })),
  tab: (index) => window.dispatchEvent(new CustomEvent('paddock:tab', { detail: index })),
})

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
    <v-defaults-provider :defaults="densityDefaults">
      <a
        class="skip-link"
        :inert="modalOpen"
        href="#main"
      >{{ t('app.skipToContent') }}</a>
      <v-app-bar
        v-if="showChrome"
        :inert="modalOpen"
        flat
        :height="44"
        class="pd-appbar"
      >
        <template #prepend>
          <v-btn
            variant="text"
            size="small"
            :icon="mobile ? 'pd:menu' : 'pd:panel-left'"
            :aria-label="navToggleLabel"
            :aria-expanded="navExpanded ? 'true' : 'false'"
            aria-controls="main-navigation"
            data-testid="nav-toggle"
            @click="toggleNav"
          />
          <img
            :src="logo"
            alt=""
            width="20"
            height="20"
            class="pd-logo"
            data-testid="app-logo"
          >
        </template>
        <v-app-bar-title class="brand">
          <span class="app-name">{{ t('app.name') }}</span>
          <template v-if="session.me?.organization">
            <span
              class="pd-brand-sep"
              aria-hidden="true"
            >/</span>
            <!-- Vuetify 4 tooltips are eager: the role=tooltip element is in the DOM before any hover and needs a
                 name of its own (axe aria-tooltip-name). -->
            <v-tooltip
              :text="session.me.organization.name"
              :aria-label="session.me.organization.name"
              location="bottom"
              open-on-click
              open-on-hover
            >
              <template #activator="{ props: tip }">
                <span
                  v-bind="tip"
                  class="org-name"
                  :title="session.me.organization.name"
                  data-testid="org-name"
                >{{ session.me.organization.name }}</span>
              </template>
            </v-tooltip>
          </template>
        </v-app-bar-title>
        <label
          v-if="!mobile"
          class="pd-command"
        >
          <PdIcon name="search" />
          <span class="visually-hidden">{{ t('app.commandField') }}</span>
          <input
            type="text"
            :placeholder="t('app.commandPlaceholder')"
            autocomplete="off"
            data-testid="command-field"
            @focus="onFieldFocus"
            @keydown.enter.prevent="openPalette"
          >
          <kbd
            class="pd-kbd"
            aria-hidden="true"
          >{{ t('shortcuts.paletteKey', { mod }) }}</kbd>
        </label>
        <template #append>
          <v-btn
            v-if="mobile"
            variant="text"
            size="small"
            icon="pd:search"
            :aria-label="t('app.commandField')"
            data-testid="command-button"
            @click="openPalette"
          />
          <RouterLink
            v-if="session.canReadGroups && attention > 0"
            to="/attention"
            class="pd-chip pd-chip--critical pd-pill"
            data-testid="app-bar-attention"
          >
            <span
              class="pd-chip-dot"
              aria-hidden="true"
            />
            {{ t('nav.attentionPill', { count: attention }) }}
          </RouterLink>
          <v-chip
            v-if="stepUpUntil && !mobile"
            size="small"
            data-testid="stepup-chip"
          >
            {{ t('app.stepUpChip', { time: stepUpUntil }) }}
          </v-chip>
          <v-btn
            variant="text"
            size="small"
            :icon="isDark ? 'pd:sun' : 'pd:moon'"
            :aria-label="t(isDark ? 'app.themeToggle.toLight' : 'app.themeToggle.toDark')"
            data-testid="theme-toggle"
            @click="chooseTheme(isDark ? 'light' : 'dark')"
          />
          <v-menu>
            <template #activator="{ props: menu }">
              <v-btn
                v-bind="menu"
                variant="text"
                class="user-button"
                :aria-label="t('app.userMenu', { name: session.me?.display_name ?? '' })"
                data-testid="user-menu"
              >
                <span
                  class="pd-avatar"
                  aria-hidden="true"
                >{{ initial }}</span>
                <span class="user-button-name">
                  <span class="pd-user-name">{{ session.me?.display_name }}</span>
                  <span class="pd-user-role pd-type-caption pd-muted">{{ roleLabel }}</span>
                </span>
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
                <v-list-item-subtitle data-testid="user-stepup">
                  {{ stepUpUntil ? t('app.stepUpValidUntil', { time: stepUpUntil }) : t('app.stepUpNone') }}
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
              <v-menu submenu>
                <template #activator="{ props: themeMenu }">
                  <v-list-item
                    v-bind="themeMenu"
                    :aria-label="t('app.themeMenu', { theme: t('app.themes.' + (session.me?.theme ?? 'system')) })"
                    data-testid="theme-menu"
                  >
                    <v-list-item-title>{{ t('app.theme') }}</v-list-item-title>
                    <v-list-item-subtitle>{{ t('app.themes.' + (session.me?.theme ?? 'system')) }}</v-list-item-subtitle>
                  </v-list-item>
                </template>
                <v-list
                  :aria-label="t('app.theme')"
                  density="compact"
                >
                  <v-list-item
                    v-for="option in (['system', 'light', 'dark'] as const)"
                    :key="option"
                    :active="option === (session.me?.theme ?? 'system')"
                    :prepend-icon="option === 'system' ? 'pd:monitor' : option === 'light' ? 'pd:sun' : 'pd:moon'"
                    :data-testid="'theme-' + option"
                    @click="chooseTheme(option)"
                  >
                    <v-list-item-title>{{ t('app.themes.' + option) }}</v-list-item-title>
                  </v-list-item>
                </v-list>
              </v-menu>
              <v-menu submenu>
                <template #activator="{ props: densityMenu }">
                  <v-list-item
                    v-bind="densityMenu"
                    :aria-label="t('app.densityMenu', { density: t('app.densities.' + density) })"
                    data-testid="density-menu"
                  >
                    <v-list-item-title>{{ t('app.density') }}</v-list-item-title>
                    <v-list-item-subtitle>{{ t('app.densities.' + density) }}</v-list-item-subtitle>
                  </v-list-item>
                </template>
                <v-list
                  :aria-label="t('app.density')"
                  density="compact"
                >
                  <v-list-item
                    v-for="option in (['compact', 'comfortable'] as const)"
                    :key="option"
                    :active="option === density"
                    :data-testid="'density-' + option"
                    @click="chooseDensity(option)"
                  >
                    <v-list-item-title>{{ t('app.densities.' + option) }}</v-list-item-title>
                  </v-list-item>
                </v-list>
              </v-menu>
              <v-list-item
                prepend-icon="pd:keyboard"
                data-testid="shortcuts-help"
                @click="helpOpen = true"
              >
                <v-list-item-title>{{ t('app.shortcuts') }}</v-list-item-title>
              </v-list-item>
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
        :permanent="!mobile"
        :temporary="mobile"
        :rail="rail"
        :aria-label="t('app.mainNavigation')"
        class="pd-nav"
        :class="{ 'pd-nav--rail': rail }"
        data-testid="nav-drawer"
      >
        <div
          ref="nav"
          class="nav-groups"
          @keydown="onNavKeydown"
        >
          <div
            v-for="group in groups"
            :key="group.key"
            class="pd-nav-group"
            role="group"
            :aria-labelledby="rail ? undefined : 'nav-group-' + group.key"
            :aria-label="rail ? t(group.label) : undefined"
            :data-testid="'nav-group-' + group.key"
          >
            <h2
              v-if="!rail"
              :id="'nav-group-' + group.key"
              class="pd-nav-heading pd-type-overline"
            >
              {{ t(group.label) }}
            </h2>
            <hr
              v-else
              class="pd-nav-divider"
              aria-hidden="true"
            >
            <RouterLink
              v-for="item in group.items"
              :key="item.to"
              :to="item.to"
              class="pd-nav-item"
              :tabindex="item.to === tabStop ? 0 : -1"
              :aria-label="rail ? t(item.label) : undefined"
              :title="rail ? undefined : item.shortcut ? t('nav.shortcut', { keys: item.shortcut }) : undefined"
              :data-testid="item.testid"
              @click="closeOnSmallScreen"
              @focus="focusedPath = item.to"
            >
              <PdIcon :name="item.icon" />
              <span class="pd-nav-label">{{ t(item.label) }}</span>
              <kbd
                v-if="item.shortcut"
                class="pd-nav-shortcut pd-type-kbd"
                aria-hidden="true"
              >{{ item.shortcut }}</kbd>
              <!-- Eager like the org-name tooltip: named so axe accepts it while hidden (aria-tooltip-name). -->
              <v-tooltip
                v-if="rail"
                activator="parent"
                :aria-label="t(item.label)"
                location="end"
              >
                {{ t(item.label) }}
              </v-tooltip>
            </RouterLink>
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
      <v-snackbar
        v-model="themeFailed"
        color="error"
      >
        {{ t('app.themeFailed') }}
      </v-snackbar>
      <CommandPalette
        v-if="showChrome"
        v-model="paletteOpen"
        :context="paletteContext"
      />
      <ShortcutHelpDialog
        v-if="showChrome"
        v-model="helpOpen"
      />
      <ConfirmDialog
        v-if="pendingConfirm"
        :key="pendingConfirm.id"
        :model-value="true"
        v-bind="pendingConfirm.options"
        @confirm="(answer) => settleConfirm(answer)"
        @cancel="settleConfirm(false)"
      />
    </v-defaults-provider>
  </v-app>
</template>
