import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'

export default defineConfig({
  // vite-plugin-vuetify imports each used component and its style sheet; styles end up in CSS files.
  plugins: [vue(), vuetify({ autoImport: true })],
  define: {
    __VUE_OPTIONS_API__: false,
    __VUE_PROD_DEVTOOLS__: false,
    __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: false,
    __VUE_I18N_FULL_INSTALL__: true,
    __VUE_I18N_LEGACY_API__: false,
    __INTLIFY_PROD_DEVTOOLS__: false,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The CSP forbids inline scripts and allows inline styles only with the per-response nonce: everything is
    // emitted as files.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    setupFiles: ['src/__tests__/setup.ts'],
    // Vuetify ships CSS imports in its modules; Vite must process them.
    server: { deps: { inline: ['vuetify'] } },
  },
})
