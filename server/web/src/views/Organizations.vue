<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import { useOrganizations } from '../lib/organizations'
import { hasErrors, validateOrganization } from '../lib/validation'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'

const { t, locale } = useI18n()
const problemText = useProblemText()
const orgs = useOrganizations()

const open = ref(false)
const slug = ref('')
const name = ref('')
const touched = ref(false)
const problem = ref('')
const errors = computed(() => validateOrganization(slug.value, name.value))
const slugError = computed(() => (touched.value && errors.value.slug ? t(errors.value.slug) : ''))
const nameError = computed(() => (touched.value && errors.value.name ? t(errors.value.name) : ''))

onMounted(() => orgs.load())

function openCreate(): void {
  slug.value = ''
  name.value = ''
  touched.value = false
  problem.value = ''
  open.value = true
}

async function submit(): Promise<void> {
  touched.value = true
  if (hasErrors(errors.value)) return
  problem.value = (await orgs.create(slug.value, name.value)) ?? ''
  if (!problem.value) open.value = false
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('organizations.title') }}</h1>
      <Button
        :label="t('organizations.create')"
        @click="openCreate"
      />
    </div>
    <p
      v-if="orgs.error.value"
      class="form-error"
      role="alert"
    >
      {{ problemText(orgs.error.value) }}
    </p>
    <DataTable
      :value="orgs.items.value"
      data-key="id"
      :loading="orgs.loading.value"
      class="table"
    >
      <template #empty>
        {{ t('common.empty') }}
      </template>
      <Column
        field="slug"
        :header="t('organizations.slug')"
      />
      <Column
        field="name"
        :header="t('common.name')"
      />
      <Column :header="t('organizations.status')">
        <template #body="{ data }">
          {{ t('organizations.statuses.' + data.status) }}
        </template>
      </Column>
      <Column :header="t('common.createdAt')">
        <template #body="{ data }">
          {{ formatDateTime(data.created_at, locale) }}
        </template>
      </Column>
    </DataTable>
    <Button
      v-if="orgs.nextCursor.value"
      :label="t('common.loadMore')"
      severity="secondary"
      @click="orgs.load(true)"
    />

    <Dialog
      v-model:visible="open"
      modal
      :header="t('organizations.createTitle')"
    >
      <form
        class="form"
        novalidate
        @submit.prevent="submit"
      >
        <div class="field">
          <label for="org-slug">{{ t('organizations.slug') }}</label>
          <InputText
            id="org-slug"
            v-model="slug"
            autocomplete="off"
            :invalid="!!slugError"
            :aria-describedby="slugError ? 'org-slug-error' : undefined"
          />
          <small
            v-if="slugError"
            id="org-slug-error"
            class="field-error"
          >{{ slugError }}</small>
        </div>
        <div class="field">
          <label for="org-name">{{ t('common.name') }}</label>
          <InputText
            id="org-name"
            v-model="name"
            autocomplete="off"
            :invalid="!!nameError"
            :aria-describedby="nameError ? 'org-name-error' : undefined"
          />
          <small
            v-if="nameError"
            id="org-name-error"
            class="field-error"
          >{{ nameError }}</small>
        </div>
        <p
          v-if="problem"
          class="form-error"
          role="alert"
        >
          {{ problemText(problem) }}
        </p>
        <div class="form-actions">
          <Button
            type="button"
            severity="secondary"
            :label="t('common.cancel')"
            @click="open = false"
          />
          <Button
            type="submit"
            :label="t('common.create')"
          />
        </div>
      </form>
    </Dialog>
  </section>
</template>
