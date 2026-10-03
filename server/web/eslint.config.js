// ESLint covers the Vue templates and the JavaScript in single-file components: no raw text in templates and no
// missing message keys (plan M0 step 8). TypeScript modules (*.ts) are checked by vue-tsc, not by ESLint, because
// the dependency set has no TypeScript parser for ESLint; component scripts therefore use plain JavaScript syntax
// and keep typed logic in src/lib and src/stores.
import pluginVue from 'eslint-plugin-vue'
import vueI18n from '@intlify/eslint-plugin-vue-i18n'

export default [
  { ignores: ['dist/**', 'node_modules/**', 'test-results/**', 'playwright-report/**', '**/*.ts'] },
  ...pluginVue.configs['flat/recommended'],
  ...vueI18n.configs.recommended,
  {
    files: ['**/*.vue'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
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
]
