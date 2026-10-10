<script setup lang="ts">
import { nextTick, ref, useId, watch, type ComponentPublicInstance } from 'vue'
import { useI18n } from 'vue-i18n'
import { modifierLabel, setSingleKeyShortcuts, singleKeyShortcutsEnabled } from '../composables/useShortcuts'
import { reducedMotion } from '../lib/pageContext'

/** The keyboard shortcuts of the portal (plan M7c decision 18) and the switch for single-key shortcuts. */
const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [open: boolean] }>()

const { t } = useI18n()
const id = useId()
const mod = modifierLabel()
const singleKey = ref(singleKeyShortcutsEnabled())
const closeButton = ref<ComponentPublicInstance | null>(null)
const rows: { keys: string[]; text: string }[] = [
  { keys: [`${mod} K`, '/'], text: 'shortcuts.palette' },
  { keys: ['Esc'], text: 'shortcuts.escape' },
  { keys: ['g o'], text: 'shortcuts.goOverview' },
  { keys: ['g a'], text: 'shortcuts.goAttention' },
  { keys: ['g d'], text: 'shortcuts.goDevices' },
  { keys: ['g s'], text: 'shortcuts.goSoftware' },
  { keys: ['g v'], text: 'shortcuts.goVulnerabilities' },
  { keys: ['g l'], text: 'shortcuts.goAudit' },
  { keys: ['j', 'k'], text: 'shortcuts.listMove' },
  { keys: ['Enter', 'o'], text: 'shortcuts.listOpen' },
  { keys: ['['], text: 'shortcuts.nav' },
  { keys: ['?'], text: 'shortcuts.help' },
  { keys: ['Alt 1', '…', 'Alt 9'], text: 'shortcuts.tabs' },
]

function focusClose(): void {
  ;(closeButton.value?.$el as HTMLElement | undefined)?.focus()
}
watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      singleKey.value = singleKeyShortcutsEnabled()
      void nextTick(focusClose)
    }
  },
)
function toggleSingleKey(value: boolean | null): void {
  singleKey.value = value === true
  setSingleKeyShortcuts(singleKey.value)
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="560"
    :transition="reducedMotion() ? false : 'dialog-transition'"
    :aria-labelledby="id + '-title'"
    @update:model-value="(open: boolean) => !open && emit('update:modelValue', false)"
    @after-enter="focusClose"
  >
    <v-card data-testid="shortcut-help">
      <v-card-title
        :id="id + '-title'"
        tag="h2"
      >
        {{ t('shortcuts.title') }}
      </v-card-title>
      <v-card-text>
        <table class="pd-shortcuts">
          <thead>
            <tr>
              <th scope="col">
                {{ t('shortcuts.keys') }}
              </th>
              <th scope="col">
                {{ t('shortcuts.action') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in rows"
              :key="row.text"
            >
              <td class="pd-shortcuts-keys">
                <kbd
                  v-for="key in row.keys"
                  :key="key"
                  class="pd-kbd"
                >{{ key }}</kbd>
              </td>
              <td>{{ t(row.text) }}</td>
            </tr>
          </tbody>
        </table>
        <v-switch
          :model-value="singleKey"
          :label="t('shortcuts.singleKey')"
          :hint="t('shortcuts.singleKeyHint', { mod })"
          persistent-hint
          color="primary"
          density="compact"
          data-testid="shortcuts-single-key"
          @update:model-value="toggleSingleKey"
        />
        <p class="pd-muted pd-type-caption">
          {{ t('shortcuts.never') }}
        </p>
        <div class="form-actions">
          <v-btn
            ref="closeButton"
            data-testid="shortcuts-close"
            @click="emit('update:modelValue', false)"
          >
            {{ t('shortcuts.close') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
