import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { router } from './router'
import { applyLocale, i18n } from './i18n'
import { vuetify } from './plugins/vuetify'
import { cachedPreference, resolveTheme, systemPrefersDark } from './lib/theme'
import './styles/tokens.css'
import './styles/fonts.css'
import './styles/typography.css'
import './styles.css'

// The --pd-* tokens follow <html data-theme> from the first paint; the session store applies the account's
// preference once GET /api/v1/me has answered.
document.documentElement.dataset.theme = resolveTheme(cachedPreference(), systemPrefersDark())
applyLocale(i18n.global.locale.value)
createApp(App).use(createPinia()).use(router).use(i18n).use(vuetify).mount('#app')
