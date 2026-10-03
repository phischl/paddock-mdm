// ESLint covers TypeScript modules and single-file components (<script setup lang="ts">): no raw text in templates
// and no missing message keys (plan M0 step 8), TypeScript rules through typescript-eslint (plan M0.1 step 3).
// vue-tsc still does the type checking.
import pluginVue from 'eslint-plugin-vue'
import vueI18n from '@intlify/eslint-plugin-vue-i18n'
import { defineConfigWithVueTs, vueTsConfigs } from '@vue/eslint-config-typescript'

export default defineConfigWithVueTs(
  {
    ignores: ['dist/**', 'node_modules/**', 'test-results/**', 'playwright-report/**', 'src/api/schema.d.ts'],
  },
  pluginVue.configs['flat/recommended'],
  vueTsConfigs.recommended,
  vueI18n.configs.recommended,
  {
    files: ['**/*.vue'],
    rules: {
      '@intlify/vue-i18n/no-raw-text': ['error', { ignorePattern: '^[-–—·:/()|•…]+$' }],
      '@intlify/vue-i18n/no-missing-keys': 'error',
      '@intlify/vue-i18n/no-v-html': 'error',
      'vue/multi-word-component-names': 'off',
    },
  },
  {
    rules: {
      // Messages are ICU MessageFormat (intl-messageformat), not vue-i18n syntax; src/__tests__ checks them.
      '@intlify/vue-i18n/valid-message-syntax': 'off',
    },
    settings: {
      'vue-i18n': {
        localeDir: './src/locales/*.json',
        messageSyntaxVersion: '^11.0.0',
      },
    },
  },
)
