<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import type { Organization } from '../api/client'
import { createOrganization, listOrganizations, organizationFilters } from '../lib/organizations'
import { hasErrors, validateOrganization } from '../lib/validation'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'

const { t, locale } = useI18n()
const problemText = useProblemText()
const list = ref<{ reload: () => Promise<void> } | null>(null)

const open = ref(false)
const slug = ref('')
const name = ref('')
const touched = ref(false)
const problem = ref('')
const errors = computed(() => validateOrganization(slug.value, name.value))
const slugError = computed(() => (touched.value && errors.value.slug ? t(errors.value.slug) : ''))
const nameError = computed(() => (touched.value && errors.value.name ? t(errors.value.name) : ''))

const columns: ListColumn[] = [
  { key: 'slug', title: 'organizations.slug', sortable: true },
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'status', title: 'organizations.status', sortable: true },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
]

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
  problem.value = (await createOrganization(slug.value, name.value)) ?? ''
  // A failed provisioning still stores the organization (status provisioning_failed).
  void list.value?.reload()
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
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listOrganizations"
      :filters="organizationFilters"
      searchable
      default-sort="slug"
      item-value="id"
      data-testid="organization-list"
    >
      <template #[`item.status`]="{ item }: { item: Organization }">
        {{ t('organizations.statuses.' + item.status) }}
      </template>
      <template #[`item.created_at`]="{ item }: { item: Organization }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
    </DataList>

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
