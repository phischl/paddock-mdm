<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
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

const headers = computed(() => [
  { title: t('organizations.slug'), key: 'slug', sortable: false },
  { title: t('common.name'), key: 'name', sortable: false },
  { title: t('organizations.status'), key: 'status', sortable: false },
  { title: t('common.createdAt'), key: 'created_at', sortable: false },
])

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
      <v-btn
        color="primary"
        @click="openCreate"
      >
        {{ t('organizations.create') }}
      </v-btn>
    </div>
    <p
      v-if="orgs.error.value"
      class="form-error"
      role="alert"
    >
      {{ problemText(orgs.error.value) }}
    </p>
    <v-data-table
      :headers="headers"
      :items="orgs.items.value"
      item-value="id"
      :items-per-page="-1"
      :loading="orgs.loading.value"
      hide-default-footer
      class="table"
    >
      <template #no-data>
        {{ t('common.empty') }}
      </template>
      <template #[`item.status`]="{ item }">
        {{ t('organizations.statuses.' + item.status) }}
      </template>
      <template #[`item.created_at`]="{ item }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
    </v-data-table>
    <v-btn
      v-if="orgs.hasMore.value"
      variant="tonal"
      @click="orgs.load(true)"
    >
      {{ t('common.loadMore') }}
    </v-btn>

    <v-dialog
      v-model="open"
      max-width="32rem"
      :aria-label="t('organizations.createTitle')"
    >
      <v-card :title="t('organizations.createTitle')">
        <v-card-text>
          <form
            class="form"
            novalidate
            @submit.prevent="submit"
          >
            <v-text-field
              id="org-slug"
              v-model="slug"
              :label="t('organizations.slug')"
              autocomplete="off"
              :error-messages="slugError ? [slugError] : []"
              :aria-invalid="!!slugError"
            />
            <v-text-field
              id="org-name"
              v-model="name"
              :label="t('common.name')"
              autocomplete="off"
              :error-messages="nameError ? [nameError] : []"
              :aria-invalid="!!nameError"
            />
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
                @click="open = false"
              >
                {{ t('common.cancel') }}
              </v-btn>
              <v-btn
                type="submit"
                color="primary"
              >
                {{ t('common.create') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
