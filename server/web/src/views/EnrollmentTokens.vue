<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import EnrollmentTokenForm from '../components/EnrollmentTokenForm.vue'
import type { EnrollmentToken, EnrollmentTokenCreated } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { allGroups } from '../lib/devices'
import { configText, createEnrollmentToken, listEnrollmentTokens, revokeEnrollmentToken, type TokenInput } from '../lib/enrollmentTokens'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const problemText = useProblemText()
const confirm = useConfirm()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)
const groups = ref<{ id: string; name: string }[]>([])
onMounted(async () => {
  groups.value = await allGroups()
})

const open = ref(false)
const problem = ref('')
const pageProblem = ref('')
// The one-time answer: shown once in the dialog and dropped when it closes.
const created = ref<EnrollmentTokenCreated | null>(null)
const copied = ref(false)

const columns = computed<ListColumn[]>(() => [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'status', title: 'tokens.status' },
  { key: 'uses', title: 'tokens.uses' },
  { key: 'expires_at', title: 'tokens.expiresAt', sortable: true },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  ...(session.canDelete ? [{ key: 'actions', title: 'common.actions' }] : []),
])

function openCreate(): void {
  problem.value = ''
  created.value = null
  copied.value = false
  open.value = true
}

function close(): void {
  open.value = false
  created.value = null
}

async function onCreate(input: TokenInput): Promise<void> {
  const res = await createEnrollmentToken(input)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  created.value = res
  void list.value?.reload()
}

async function copy(): Promise<void> {
  if (!created.value) return
  await navigator.clipboard.writeText(configText(created.value))
  copied.value = true
}

async function onRevoke(token: EnrollmentToken): Promise<void> {
  pageProblem.value = ''
  const confirmed = await confirm({
    title: t('tokens.revokeTitle'),
    message: t('tokens.revokeConfirm', { name: token.name }),
    confirmLabel: t('tokens.revoke'),
    destructive: true,
  })
  if (!confirmed) return
  pageProblem.value = (await revokeEnrollmentToken(token.id)) ?? ''
  void list.value?.reload()
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('tokens.title') }}</h1>
      <v-btn
        v-if="session.canDelete"
        color="primary"
        data-testid="create-token"
        @click="openCreate"
      >
        {{ t('tokens.create') }}
      </v-btn>
    </div>
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
      :fetch="listEnrollmentTokens"
      searchable
      default-sort="-created_at"
      item-value="id"
      data-testid="token-list"
    >
      <template #[`item.status`]="{ item }: { item: EnrollmentToken }">
        {{ t('tokens.statuses.' + item.status) }}
      </template>
      <template #[`item.uses`]="{ item }: { item: EnrollmentToken }">
        {{ t('tokens.usesOf', { uses: item.uses, max: item.max_uses }) }}
      </template>
      <template #[`item.expires_at`]="{ item }: { item: EnrollmentToken }">
        {{ formatDateTime(item.expires_at, locale) }}
      </template>
      <template #[`item.created_at`]="{ item }: { item: EnrollmentToken }">
        {{ formatDateTime(item.created_at, locale) }}
      </template>
      <template #[`item.actions`]="{ item }: { item: EnrollmentToken }">
        <v-btn
          v-if="item.status === 'active'"
          :aria-label="t('tokens.revokeLabel', { name: item.name })"
          color="error"
          size="small"
          @click="onRevoke(item)"
        >
          {{ t('tokens.revoke') }}
        </v-btn>
      </template>
    </DataList>

    <v-dialog
      :model-value="open"
      max-width="40rem"
      :aria-label="t('tokens.createTitle')"
      persistent
      @update:model-value="(v: boolean) => !v && close()"
    >
      <v-card :title="t('tokens.createTitle')">
        <v-card-text v-if="!created">
          <EnrollmentTokenForm
            :groups="groups"
            :problem="problem"
            @submit="onCreate"
            @cancel="close"
          />
        </v-card-text>
        <v-card-text v-else>
          <v-alert
            type="warning"
            variant="tonal"
          >
            {{ t('tokens.shownOnce') }}
          </v-alert>
          <v-textarea
            :model-value="configText(created)"
            :label="t('tokens.config')"
            readonly
            rows="10"
            class="config-text"
            data-testid="enrollment-config"
          />
          <div class="form-actions">
            <span
              v-if="copied"
              role="status"
            >{{ t('tokens.copied') }}</span>
            <v-btn
              variant="tonal"
              data-testid="copy-config"
              @click="copy"
            >
              {{ t('tokens.copy') }}
            </v-btn>
            <v-btn
              color="primary"
              data-testid="close-token"
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
