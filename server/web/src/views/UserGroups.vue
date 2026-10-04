<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import DataList from '../components/DataList.vue'
import type { UpstreamGroup, UserGroup } from '../api/client'
import { formatDateTime } from '../lib/format'
import { searchText, type ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { createUserGroup, groupSlugPattern, groupSourceFilter, listUpstreamGroups, listUserGroups, slugFrom } from '../lib/userGroups'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const router = useRouter()
const problemText = useProblemText()
const session = useSessionStore()

// One dialog for both kinds: a local group, or an import of an upstream group (upstream set).
const open = ref(false)
const importing = ref(false)
const slug = ref('')
const name = ref('')
const upstream = ref<UpstreamGroup | null>(null)
const upstreamSearch = ref('')
const upstreamItems = ref<UpstreamGroup[]>([])
const touched = ref(false)
const problem = ref('')
const slugError = computed(() => (touched.value && !groupSlugPattern.test(slug.value) ? t('userGroups.slugInvalid') : ''))
const nameError = computed(() => (touched.value && name.value.trim() === '' ? t('validation.nameRequired') : ''))
const upstreamError = computed(() => (touched.value && importing.value && !upstream.value ? t('userGroups.upstreamRequired') : ''))

const columns: ListColumn[] = [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'slug', title: 'userGroups.slug', sortable: true },
  { key: 'source', title: 'users.source' },
  { key: 'authentik_name', title: 'userGroups.authentikName' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
]

function openDialog(asImport: boolean): void {
  importing.value = asImport
  slug.value = ''
  name.value = ''
  upstream.value = null
  upstreamSearch.value = ''
  touched.value = false
  problem.value = ''
  open.value = true
  if (asImport) void searchUpstream('')
}

async function searchUpstream(text: string): Promise<void> {
  try {
    const page = await listUpstreamGroups({ page: 1, page_size: 25, sort: 'name', q: searchText(text) })
    upstreamItems.value = page.items
  } catch {
    upstreamItems.value = []
  }
}
watch(upstreamSearch, (v) => void searchUpstream(v ?? ''))
watch(upstream, (g) => {
  if (!g) return
  if (!name.value) name.value = g.name
  if (!slug.value) slug.value = slugFrom(g.name)
})

async function submit(): Promise<void> {
  touched.value = true
  if (slugError.value || nameError.value || upstreamError.value) return
  const res = await createUserGroup(slug.value, name.value, importing.value ? (upstream.value?.id ?? null) : null)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  open.value = false
  await router.push({ name: 'user-group', params: { id: res.id } })
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('userGroups.title') }}</h1>
      <div
        v-if="session.canWrite"
        class="row-actions"
      >
        <v-btn
          variant="tonal"
          data-testid="import-user-group"
          @click="openDialog(true)"
        >
          {{ t('userGroups.import') }}
        </v-btn>
        <v-btn
          color="primary"
          data-testid="create-user-group"
          @click="openDialog(false)"
        >
          {{ t('userGroups.create') }}
        </v-btn>
      </div>
    </div>
    <DataList
      :columns="columns"
      :fetch="listUserGroups"
      :filters="[groupSourceFilter]"
      searchable
      default-sort="name"
      item-value="id"
      data-testid="user-group-list"
    >
      <template #[`item.name`]="{ item }: { item: UserGroup }">
        <RouterLink :to="{ name: 'user-group', params: { id: item.id } }">
          {{ item.name }}
        </RouterLink>
      </template>
      <template #[`item.source`]="{ item }: { item: UserGroup }">
        <span :class="'badge badge-' + item.source">{{ t('userGroups.sources.' + item.source) }}</span>
      </template>
      <template #[`item.created_at`]="{ item }: { item: UserGroup }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
    </DataList>

    <v-dialog
      v-model="open"
      max-width="36rem"
      :aria-label="t(importing ? 'userGroups.importTitle' : 'userGroups.createTitle')"
    >
      <v-card :title="t(importing ? 'userGroups.importTitle' : 'userGroups.createTitle')">
        <v-card-text>
          <form
            class="form"
            novalidate
            @submit.prevent="submit"
          >
            <v-autocomplete
              v-if="importing"
              id="group-upstream"
              v-model="upstream"
              v-model:search="upstreamSearch"
              :items="upstreamItems"
              item-title="name"
              return-object
              no-filter
              :label="t('userGroups.upstreamGroup')"
              :hint="t('userGroups.importHint')"
              persistent-hint
              :error-messages="upstreamError ? [upstreamError] : []"
              data-testid="upstream-group"
            />
            <v-text-field
              id="group-name"
              v-model="name"
              :label="t('common.name')"
              autocomplete="off"
              :error-messages="nameError ? [nameError] : []"
            />
            <v-text-field
              id="group-slug"
              v-model="slug"
              :label="t('userGroups.slug')"
              :hint="t('userGroups.slugHint')"
              persistent-hint
              autocomplete="off"
              :error-messages="slugError ? [slugError] : []"
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
                {{ t(importing ? 'userGroups.importAction' : 'common.create') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
