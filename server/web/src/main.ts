import { createApp } from 'vue'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import Base from '@primevue/core/base'
import VirtualScrollerStyle from 'primevue/virtualscroller/style'
import App from './App.vue'
import { router } from './router'
import { createPortalI18n } from './i18n'
import './styles.css'

// Even in unstyled mode PrimeVue injects its base CSS as <style> elements, which the strict CSP (no inline styles)
// blocks. All styling lives in styles.css, so every PrimeVue style sheet is reported as already loaded.
Base.isStyleNameLoaded = () => true
// The virtual scroller inside DataTable loads its CSS without consulting that registry.
const virtualScrollerStyle = VirtualScrollerStyle as unknown as { loadCSS: () => object }
virtualScrollerStyle.loadCSS = () => ({})

createApp(App)
  .use(createPinia())
  .use(router)
  .use(createPortalI18n())
  // Unstyled mode: PrimeVue injects no <style> elements, so the strict CSP holds; styles live in styles.css.
  .use(PrimeVue, { unstyled: true })
  .mount('#app')
