<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PackageRef, SoftwareCatalogEntry } from '../api/client'
import { useProblemText } from '../lib/problems'
import { emptyPackageRef, entryHasErrors, validateEntry, type EntryInput } from '../lib/software'

/** Create and edit form of a catalog entry with the editor of its package rows (plan M13a decision 8). */
const props = withDefaults(
  defineProps<{ sources: { id: string; name: string }[]; initial?: SoftwareCatalogEntry | null; problem?: string; pending?: boolean }>(),
  { initial: null, problem: '', pending: false },
)
const emit = defineEmits<{ submit: [input: EntryInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const name = ref(props.initial?.name ?? '')
const description = ref(props.initial?.description ?? '')
const category = ref(props.initial?.category ?? '')
const sourceID = ref<string | null>(props.initial?.source_id ?? null)
const packages = ref<PackageRef[]>(props.initial ? props.initial.packages.map((p) => ({ ...p })) : [emptyPackageRef()])
const touched = ref(false)
const input = computed<EntryInput>(() => ({
  name: name.value, description: description.value, category: category.value, sourceID: sourceID.value, packages: packages.value,
}))
const errors = computed(() => validateEntry(input.value))
const architectures = computed(() => [
  { value: '*', title: t('software.catalog.anyArchitecture') },
  { value: 'amd64', title: 'amd64' },
  { value: 'arm64', title: 'arm64' },
])

function submit(): void {
  touched.value = true
  if (entryHasErrors(errors.value)) return
  emit('submit', { ...input.value, name: name.value.trim(), category: category.value.trim() })
}

function message(key: string | undefined): string[] {
  return touched.value && key ? [t(key)] : []
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-text-field
      id="entry-name"
      v-model="name"
      :label="t('software.catalog.name')"
      autocomplete="off"
      :error-messages="message(errors.name)"
      data-testid="entry-name"
    />
    <v-textarea
      id="entry-description"
      v-model="description"
      :label="t('software.catalog.description')"
      rows="2"
      auto-grow
      counter="1000"
      :error-messages="message(errors.description)"
      data-testid="entry-description"
    />
    <v-text-field
      id="entry-category"
      v-model="category"
      :label="t('software.catalog.category')"
      autocomplete="off"
      :error-messages="message(errors.category)"
      data-testid="entry-category"
    />
    <v-select
      id="entry-source"
      v-model="sourceID"
      :label="t('software.catalog.source')"
      :hint="t('software.catalog.sourceHint')"
      persistent-hint
      :items="[{ value: null, title: t('software.catalog.distributionRepositories') }, ...props.sources.map((s) => ({ value: s.id, title: s.name }))]"
      data-testid="entry-source"
    />
    <fieldset class="entry-packages">
      <legend>{{ t('software.catalog.packages') }}</legend>
      <p class="summary">
        {{ t('software.catalog.packagesHint') }}
      </p>
      <div
        v-for="(row, i) in packages"
        :key="i"
        class="package-row"
        data-testid="package-row"
      >
        <v-text-field
          v-model="row.distribution"
          :label="t('software.catalog.distribution')"
          autocomplete="off"
          spellcheck="false"
          :error-messages="message(errors.rows[i]?.distribution)"
          :data-testid="'package-distribution-' + i"
        />
        <v-text-field
          v-model="row.release"
          :label="t('software.catalog.release')"
          autocomplete="off"
          spellcheck="false"
          :error-messages="message(errors.rows[i]?.release)"
          :data-testid="'package-release-' + i"
        />
        <v-select
          v-model="row.architecture"
          :label="t('software.catalog.architecture')"
          :items="architectures"
          :data-testid="'package-architecture-' + i"
        />
        <v-text-field
          v-model="row.package"
          :label="t('software.catalog.package')"
          autocomplete="off"
          spellcheck="false"
          :error-messages="message(errors.rows[i]?.package)"
          :data-testid="'package-name-' + i"
        />
        <v-btn
          type="button"
          variant="tonal"
          size="small"
          :disabled="packages.length <= 1"
          :aria-label="t('software.catalog.removeRow', { n: i + 1 })"
          @click="packages.splice(i, 1)"
        >
          {{ t('software.catalog.remove') }}
        </v-btn>
      </div>
      <p
        v-if="touched && errors.packages"
        class="form-error"
        role="alert"
      >
        {{ t(errors.packages) }}
      </p>
      <v-btn
        type="button"
        variant="tonal"
        size="small"
        :disabled="packages.length >= 20"
        data-testid="add-package-row"
        @click="packages.push(emptyPackageRef())"
      >
        {{ t('software.catalog.addRow') }}
      </v-btn>
    </fieldset>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <div class="form-actions">
      <v-btn
        type="button"
        variant="tonal"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </v-btn>
      <v-btn
        type="submit"
        color="primary"
        :loading="pending"
        :disabled="pending"
        data-testid="save-entry"
      >
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>

<style scoped>
.package-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
  gap: 0.5rem;
  align-items: start;
}
</style>
