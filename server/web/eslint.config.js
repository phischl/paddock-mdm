// ESLint covers TypeScript modules and single-file components (<script setup lang="ts">): no raw text in templates
// and no missing message keys (plan M0 step 8), TypeScript rules through typescript-eslint (plan M0.1 step 3), no
// browser-native dialogs (ADR 0018, plan M0.2 step 3). vue-tsc still does the type checking.
import pluginVue from 'eslint-plugin-vue'
import vueI18n from '@intlify/eslint-plugin-vue-i18n'
import { defineConfigWithVueTs, vueTsConfigs } from '@vue/eslint-config-typescript'

// ADR 0018: every confirmation is a modal (ConfirmDialog), every message an inline alert or snackbar.
const nativeDialog = 'Browser-native dialogs are forbidden (ADR 0018): use ConfirmDialog (useConfirm) or an inline alert.'
const nativeDialogs = ['alert', 'confirm', 'prompt']

export default defineConfigWithVueTs(
  {
    ignores: [
      'dist/**', 'node_modules/**', 'test-results/**', 'playwright-report/**', 'src/api/schema.d.ts',
      // Code that must fail the rules below; src/__tests__/lint.test.ts proves it does.
      'lint-fixtures/**',
    ],
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
      'no-alert': 'error',
      'no-restricted-globals': ['error', ...nativeDialogs.map((name) => ({ name, message: nativeDialog }))],
      'no-restricted-properties': [
        'error',
        ...['window', 'globalThis', 'self'].flatMap((object) =>
          nativeDialogs.map((property) => ({ object, property, message: nativeDialog })),
        ),
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.property.name='addEventListener'][arguments.0.value='beforeunload']",
          message: 'beforeunload prompts are forbidden (ADR 0018).',
        },
        {
          selector: "AssignmentExpression[left.property.name='onbeforeunload']",
          message: 'beforeunload prompts are forbidden (ADR 0018).',
        },
      ],
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
