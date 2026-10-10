<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { paletteEntries, type PaletteContext, type PaletteEntry, type PaletteGroup } from '../lib/commands'
import { reducedMotion } from '../lib/pageContext'
import PdIcon from './PdIcon'

/**
 * The command palette (plan M7c decision 16): a combobox over grouped options — pages, devices, device groups, a
 * CVE and non-destructive actions. Up/Down move, Enter runs, Esc closes.
 */
const props = defineProps<{
  modelValue: boolean
  context: PaletteContext
}>()
const emit = defineEmits<{ 'update:modelValue': [open: boolean] }>()

/** Debounce of the device and group searches (plan M7c §10: 100–200 ms). */
const searchDelay = 150
const groupOrder: PaletteGroup[] = ['pages', 'devices', 'groups', 'cve', 'actions']

const { t } = useI18n()
const id = useId()
const input = ref<HTMLInputElement | null>(null)
const query = ref('')
const entries = ref<PaletteEntry[]>([])
const active = ref(0)
let timer: ReturnType<typeof setTimeout> | undefined
let request = 0

async function load(): Promise<void> {
  const current = ++request
  const result = await paletteEntries(query.value, props.context)
  if (current !== request) return
  entries.value = result
  active.value = 0
}

watch(query, () => {
  clearTimeout(timer)
  timer = setTimeout(() => void load(), searchDelay)
})
watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    query.value = ''
    void load()
    void nextTick(() => input.value?.focus())
  },
)
onBeforeUnmount(() => clearTimeout(timer))

const groups = computed(() =>
  groupOrder.map((group) => ({ group, items: entries.value.filter((e) => e.group === group) })).filter((g) => g.items.length > 0),
)
const optionId = (entry: PaletteEntry) => `${id}-option-${entry.id.replace(/[^a-zA-Z0-9_-]/g, '_')}`
const activeEntry = computed(() => entries.value[active.value])

function close(): void {
  emit('update:modelValue', false)
}
function run(entry: PaletteEntry): void {
  close()
  entry.run()
}
function move(delta: number): void {
  const n = entries.value.length
  if (n === 0) return
  active.value = (active.value + delta + n) % n
  document.getElementById(optionId(entries.value[active.value]))?.scrollIntoView({ block: 'nearest' })
}
function onKeydown(e: KeyboardEvent): void {
  switch (e.key) {
    case 'ArrowDown':
      e.preventDefault()
      return move(1)
    case 'ArrowUp':
      e.preventDefault()
      return move(-1)
    case 'Enter':
      e.preventDefault()
      if (activeEntry.value) run(activeEntry.value)
      return
    case 'Escape':
      e.preventDefault()
      return close()
  }
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="640"
    :transition="reducedMotion() ? false : 'dialog-transition'"
    :aria-label="t('palette.title')"
    class="pd-palette-dialog"
    @update:model-value="(open: boolean) => !open && close()"
    @after-enter="input?.focus()"
  >
    <div
      class="pd-palette"
      data-testid="command-palette"
    >
      <div class="pd-palette-field">
        <PdIcon name="search" />
        <label
          :for="id + '-input'"
          class="visually-hidden"
        >{{ t('app.commandField') }}</label>
        <input
          :id="id + '-input'"
          ref="input"
          v-model="query"
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-autocomplete="list"
          :aria-controls="id + '-listbox'"
          :aria-activedescendant="activeEntry ? optionId(activeEntry) : undefined"
          :placeholder="t('palette.placeholder')"
          autocomplete="off"
          spellcheck="false"
          data-testid="palette-input"
          @keydown="onKeydown"
        >
        <kbd class="pd-kbd">{{ t('shortcuts.keyEsc') }}</kbd>
      </div>
      <ul
        :id="id + '-listbox'"
        role="listbox"
        :aria-label="t('palette.title')"
        class="pd-palette-list"
      >
        <template
          v-for="g in groups"
          :key="g.group"
        >
          <li
            role="presentation"
            class="pd-palette-group pd-type-overline"
          >
            {{ t('palette.groups.' + g.group) }}
          </li>
          <li
            v-for="entry in g.items"
            :id="optionId(entry)"
            :key="entry.id"
            role="option"
            :aria-selected="entry === activeEntry"
            class="pd-palette-option"
            :class="{ 'pd-palette-option--active': entry === activeEntry }"
            :data-testid="'palette-' + entry.group"
            @mousemove="active = entries.indexOf(entry)"
            @click="run(entry)"
          >
            <span class="pd-palette-label">{{ entry.label }}</span>
            <kbd
              v-if="entry.hint"
              class="pd-kbd"
              aria-hidden="true"
            >{{ entry.hint }}</kbd>
          </li>
        </template>
        <li
          v-if="entries.length === 0"
          role="presentation"
          class="pd-palette-empty pd-muted"
        >
          {{ t('palette.noMatches') }}
        </li>
      </ul>
    </div>
  </v-dialog>
</template>
