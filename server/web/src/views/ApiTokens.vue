<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import ApiTokenForm from '../components/ApiTokenForm.vue'
import DataList from '../components/DataList.vue'
import type { ApiToken, ApiTokenCreated } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { apiTokenFilters, createApiToken, listApiTokens, revokeApiToken, type ApiTokenInput } from '../lib/apiTokens'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const problemText = useProblemText()
const confirm = useConfirm()
const router = useRouter()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)

const open = ref(false)
const problem = ref('')
const pageProblem = ref('')
// The one-time answer: shown once in the dialog and dropped when it closes.
const created = ref<ApiTokenCreated | null>(null)
const copied = ref(false)

const columns = computed<ListColumn[]>(() => [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'prefix', title: 'apiTokens.prefix' },
  { key: 'role', title: 'apiTokens.role' },
  { key: 'status', title: 'apiTokens.status' },
  { key: 'created_by', title: 'apiTokens.createdBy' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  { key: 'expires_at', title: 'apiTokens.expires', sortable: true },
  { key: 'last_used_at', title: 'apiTokens.lastUsed', sortable: true },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions' }] : []),
])

/** Creating a token needs a step-up (plan M6c decision 4): a refused creation is repeated once after it. */
onMounted(async () => {
  const resumed = resumeStepUp<ApiTokenInput>('api-token-create', 'api-tokens')
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  problem.value = ''
  created.value = null
  open.value = true
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  await create(resumed.payload, false)
})

function openCreate(): void {
  problem.value = ''
  created.value = null
  copied.value = false
  open.value = true
}

function close(): void {
  open.value = false
  created.value = null
  void list.value?.reload()
}

async function create(input: ApiTokenInput, stepUp: boolean): Promise<void> {
  const res = await createApiToken(input)
  if (typeof res === 'string') {
    if (res === stepUpRequired && stepUp) {
      startStepUp('api-token-create', 'api-tokens', input)
      return
    }
    problem.value = res
    return
  }
  created.value = res
}

async function copy(): Promise<void> {
  if (!created.value) return
  await navigator.clipboard.writeText(created.value.secret)
  copied.value = true
}

/** Organization administrators revoke every token, operators the tokens they created. */
function canRevoke(token: ApiToken): boolean {
  return token.status === 'active' && (session.canDelete || (session.canWrite && token.created_by.id === session.me?.id))
}

async function onRevoke(token: ApiToken): Promise<void> {
  pageProblem.value = ''
  const confirmed = await confirm({
    title: t('apiTokens.revokeTitle'),
    message: t('apiTokens.revokeConfirm', { name: token.name }),
    confirmLabel: t('apiTokens.revoke'),
    destructive: true,
  })
  if (!confirmed) return
  pageProblem.value = (await revokeApiToken(token.id)) ?? ''
  void list.value?.reload()
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('apiTokens.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        color="primary"
        data-testid="create-api-token"
        @click="openCreate"
      >
        {{ t('apiTokens.create') }}
      </v-btn>
    </div>
    <p class="summary">
      {{ t('apiTokens.summary') }}
    </p>
    <p
      v-if="pageProblem"
      class="form-error"
      role="alert"
    >
      {{ problemText(pageProblem) }}
    </p>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listApiTokens"
      :filters="apiTokenFilters"
      searchable
      default-sort="name"
      item-value="id"
      data-testid="api-token-list"
    >
      <template #[`item.name`]="{ item }: { item: ApiToken }">
        <span :class="{ 'token-inactive': item.status !== 'active' }">{{ item.name }}</span>
      </template>
      <template #[`item.prefix`]="{ item }: { item: ApiToken }">
        <code>{{ item.prefix }}…</code>
      </template>
      <template #[`item.role`]="{ item }: { item: ApiToken }">
        {{ t('apiTokens.roles.' + item.role) }}
      </template>
      <template #[`item.status`]="{ item }: { item: ApiToken }">
        <v-chip
          size="small"
          :color="item.status === 'active' ? 'success' : undefined"
          :variant="item.status === 'active' ? 'tonal' : 'outlined'"
          :data-testid="'api-token-status-' + item.status"
        >
          {{ t('apiTokens.statuses.' + item.status) }}
        </v-chip>
      </template>
      <template #[`item.created_by`]="{ item }: { item: ApiToken }">
        {{ item.created_by.display }}
      </template>
      <template #[`item.created_at`]="{ item }: { item: ApiToken }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
      <template #[`item.expires_at`]="{ item }: { item: ApiToken }">
        {{ formatDateTime(item.expires_at, locale) }}
      </template>
      <template #[`item.last_used_at`]="{ item }: { item: ApiToken }">
        {{ item.last_used_at ? formatDateTime(item.last_used_at, locale) : t('apiTokens.neverUsed') }}
      </template>
      <template #[`item.actions`]="{ item }: { item: ApiToken }">
        <v-btn
          v-if="canRevoke(item)"
          :aria-label="t('apiTokens.revokeLabel', { name: item.name })"
          color="error"
          size="small"
          @click="onRevoke(item)"
        >
          {{ t('apiTokens.revoke') }}
        </v-btn>
      </template>
    </DataList>

    <v-dialog
      :model-value="open"
      max-width="40rem"
      :aria-label="t('apiTokens.createTitle')"
      persistent
      @update:model-value="(v: boolean) => !v && close()"
    >
      <v-card :title="t('apiTokens.createTitle')">
        <v-card-text v-if="!created">
          <ApiTokenForm
            :creator-role="session.role"
            :problem="problem"
            @submit="(input: ApiTokenInput) => create(input, true)"
            @cancel="close"
          />
        </v-card-text>
        <v-card-text v-else>
          <v-alert
            type="warning"
            variant="tonal"
          >
            {{ t('apiTokens.shownOnce') }}
          </v-alert>
          <v-text-field
            :model-value="created.secret"
            :label="t('apiTokens.secret')"
            readonly
            class="config-text"
            data-testid="api-token-secret"
          />
          <div class="form-actions">
            <span
              v-if="copied"
              role="status"
            >{{ t('tokens.copied') }}</span>
            <v-btn
              variant="tonal"
              data-testid="copy-api-token"
              @click="copy"
            >
              {{ t('tokens.copy') }}
            </v-btn>
            <v-btn
              color="primary"
              data-testid="close-api-token"
              @click="close"
            >
              {{ t('tokens.done') }}
            </v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>

<style scoped>
.token-inactive { color: var(--muted); }
</style>
