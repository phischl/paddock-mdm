<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import type { User, UserCreated } from '../api/client'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { createUser, listUsers, userFilters } from '../lib/users'
import { useSessionStore } from '../stores/session'
import { userLockStatus } from '../lib/status'
import { usePending } from '../composables/usePending'

const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const session = useSessionStore()
const list = ref<{ reload: () => Promise<void> } | null>(null)

const open = ref(false)
const username = ref('')
const displayName = ref('')
const email = ref('')
const touched = ref(false)
const problem = ref('')
// The one-time answer: the recovery link is shown once in the dialog and dropped when it closes.
const created = ref<UserCreated | null>(null)
const copied = ref(false)
const usernameError = computed(() => (touched.value && !/^[^@\s]+@[^@\s]+$/.test(username.value.trim()) ? t('users.usernameInvalid') : ''))
const nameError = computed(() => (touched.value && displayName.value.trim() === '' ? t('validation.nameRequired') : ''))

const columns: ListColumn[] = [
  { key: 'username', title: 'users.username', sortable: true },
  { key: 'display_name', title: 'users.displayName', sortable: true },
  { key: 'source', title: 'users.source' },
  { key: 'locked', title: 'users.lockState' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
]

function openCreate(): void {
  username.value = ''
  displayName.value = ''
  email.value = ''
  touched.value = false
  problem.value = ''
  created.value = null
  copied.value = false
  open.value = true
}

function close(): void {
  open.value = false
  created.value = null
}

async function submit(): Promise<void> {
  touched.value = true
  if (usernameError.value || nameError.value) return
  const res = await createUser({ username: username.value, displayName: displayName.value, email: email.value })
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  created.value = res
  void list.value?.reload()
}

async function copy(): Promise<void> {
  if (!created.value) return
  await navigator.clipboard.writeText(created.value.recovery_link)
  copied.value = true
}
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('users.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        color="primary"
        data-testid="create-user"
        @click="openCreate"
      >
        {{ t('users.create') }}
      </v-btn>
    </div>
    <v-alert
      v-if="(session.me?.organization?.domains.length ?? 1) === 0"
      type="warning"
      variant="tonal"
      data-testid="org-no-domains"
    >
      {{ t('users.orgNoDomains') }}
    </v-alert>
    <DataList
      ref="list"
      :columns="columns"
      :fetch="listUsers"
      :filters="userFilters"
      searchable
      default-sort="username"
      item-value="id"
      empty-icon="user"
      empty-title="users.empty.title"
      empty-description="users.empty.description"
      data-testid="user-list"
    >
      <template #empty-action>
        <v-btn
          v-if="session.canWrite"
          color="primary"
          @click="openCreate"
        >
          {{ t('users.create') }}
        </v-btn>
      </template>
      <template #[`item.username`]="{ item }: { item: User }">
        <RouterLink :to="{ name: 'user', params: { id: item.id } }">
          {{ item.username }}
        </RouterLink>
        <StatusChip
          v-if="!item.domain_match"
          status="warn"
          :label="t('users.noDomain')"
          :data-testid="'no-domain-' + item.id"
        />
      </template>
      <template #[`item.source`]="{ item }: { item: User }">
        <StatusChip
          status="neutral"
          :label="t('users.sources.' + item.source)"
        />
      </template>
      <template #[`item.locked`]="{ item }: { item: User }">
        <StatusChip
          :status="userLockStatus(item.locked).status"
          :label="t(item.locked ? 'users.locked' : 'users.notLocked')"
        />
      </template>
      <template #[`item.created_at`]="{ item }: { item: User }">
        <TimeCell :iso="item.created_at" />
      </template>
    </DataList>

    <v-dialog
      :model-value="open"
      max-width="40rem"
      :aria-label="t('users.createTitle')"
      persistent
      @update:model-value="(v: boolean) => !v && close()"
    >
      <v-card :title="t('users.createTitle')">
        <v-card-text v-if="!created">
          <form
            class="form"
            novalidate
            @submit.prevent="run(submit)"
          >
            <v-text-field
              id="user-username"
              v-model="username"
              :label="t('users.username')"
              :hint="t('users.usernameHint')"
              persistent-hint
              autocomplete="off"
              :error-messages="usernameError ? [usernameError] : []"
            />
            <v-text-field
              id="user-display-name"
              v-model="displayName"
              :label="t('users.displayName')"
              autocomplete="off"
              :error-messages="nameError ? [nameError] : []"
            />
            <v-text-field
              id="user-email"
              v-model="email"
              :label="t('users.email')"
              type="email"
              autocomplete="off"
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
                @click="close"
              >
                {{ t('common.cancel') }}
              </v-btn>
              <v-btn
                type="submit"
                :loading="pending"
                :disabled="pending"
                color="primary"
              >
                {{ t('common.create') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
        <v-card-text v-else>
          <v-alert
            type="warning"
            variant="tonal"
          >
            {{ t('users.linkShownOnce', { username: created.user.username }) }}
          </v-alert>
          <v-text-field
            :model-value="created.recovery_link"
            :label="t('users.recoveryLink')"
            readonly
            data-testid="recovery-link"
          />
          <div class="form-actions">
            <span
              v-if="copied"
              role="status"
            >{{ t('tokens.copied') }}</span>
            <v-btn
              variant="tonal"
              data-testid="copy-link"
              @click="copy"
            >
              {{ t('tokens.copy') }}
            </v-btn>
            <v-btn
              color="primary"
              data-testid="close-user"
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
