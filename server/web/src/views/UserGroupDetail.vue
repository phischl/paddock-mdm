<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import type { User, UserGroup } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import { addMember, deleteUserGroup, getUserGroup, removeMember, renameUserGroup } from '../lib/userGroups'
import { allUsers, listGroupMembers, userFilters } from '../lib/users'
import { useSessionStore } from '../stores/session'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const id = computed(() => String(route.params.id))
const list = ref<{ reload: () => Promise<void> } | null>(null)

const group = ref<UserGroup | null>(null)
const problem = ref('')
const users = ref<User[]>([])
const newMember = ref<string | null>(null)
const renameOpen = ref(false)
const newName = ref('')
const local = computed(() => group.value?.source === 'local')
const fetchMembers = computed(() => listGroupMembers(id.value))

const columns = computed<ListColumn[]>(() => [
  { key: 'username', title: 'users.username', sortable: true },
  { key: 'display_name', title: 'users.displayName', sortable: true },
  { key: 'source', title: 'users.source' },
  ...(session.canWrite && local.value ? [{ key: 'actions', title: 'common.actions' }] : []),
])

async function load(): Promise<void> {
  const g = await getUserGroup(id.value)
  if (typeof g === 'string') {
    problem.value = g
    return
  }
  group.value = g
}

onMounted(async () => {
  await load()
  if (session.canWrite) users.value = await allUsers()
})

async function add(): Promise<void> {
  if (!newMember.value) return
  problem.value = (await addMember(id.value, newMember.value)) ?? ''
  newMember.value = null
  void list.value?.reload()
}

async function remove(u: User): Promise<void> {
  const confirmed = await confirm({
    title: t('userGroups.removeTitle'), message: t('userGroups.removeConfirm', { username: u.username, group: group.value?.name ?? '' }),
    confirmLabel: t('userGroups.remove'), destructive: true,
  })
  if (!confirmed) return
  problem.value = (await removeMember(id.value, u.id)) ?? ''
  void list.value?.reload()
}

async function rename(): Promise<void> {
  problem.value = (await renameUserGroup(id.value, newName.value)) ?? ''
  renameOpen.value = false
  await load()
}

async function onDelete(): Promise<void> {
  if (!group.value) return
  const confirmed = await confirm({
    title: t('userGroups.deleteTitle'), message: t('userGroups.deleteConfirm', { name: group.value.name }),
    confirmLabel: t('common.delete'), destructive: true, requireTypedText: group.value.slug,
  })
  if (!confirmed) return
  problem.value = (await deleteUserGroup(id.value)) ?? ''
  if (!problem.value) await router.push({ name: 'user-groups' })
}
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'user-groups' }">
        {{ t('userGroups.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="group">
      <div class="page-header">
        <h1>{{ group.name }}</h1>
        <div class="row-actions">
          <v-btn
            v-if="session.canWrite"
            variant="tonal"
            @click="newName = group.name; renameOpen = true"
          >
            {{ t('userGroups.rename') }}
          </v-btn>
          <v-btn
            v-if="session.canDelete"
            color="error"
            data-testid="delete-user-group"
            @click="onDelete"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </div>
      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('userGroups.authentikName') }}
            </th>
            <td>{{ group.authentik_name }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('users.source') }}
            </th>
            <td>{{ t('userGroups.sources.' + group.source) }}</td>
          </tr>
        </tbody>
      </v-table>
      <v-alert
        v-if="!local"
        type="info"
        variant="tonal"
        class="conflict"
      >
        {{ t('userGroups.mirrorHint') }}
      </v-alert>

      <h2>{{ t('userGroups.members') }}</h2>
      <form
        v-if="session.canWrite && local"
        class="form groups-form"
        novalidate
        @submit.prevent="add"
      >
        <v-autocomplete
          v-model="newMember"
          :items="users.map((u) => ({ value: u.id, title: u.username }))"
          :label="t('userGroups.addMember')"
          data-testid="add-member"
        />
        <div class="form-actions">
          <v-btn
            type="submit"
            color="primary"
            :disabled="!newMember"
            data-testid="add-member-submit"
          >
            {{ t('userGroups.add') }}
          </v-btn>
        </div>
      </form>
      <DataList
        ref="list"
        :columns="columns"
        :fetch="fetchMembers"
        :filters="userFilters"
        searchable
        default-sort="username"
        item-value="id"
        data-testid="member-list"
      >
        <template #[`item.username`]="{ item }: { item: User }">
          <RouterLink :to="{ name: 'user', params: { id: item.id } }">
            {{ item.username }}
          </RouterLink>
        </template>
        <template #[`item.source`]="{ item }: { item: User }">
          {{ t('users.sources.' + item.source) }}
        </template>
        <template #[`item.actions`]="{ item }: { item: User }">
          <v-btn
            :aria-label="t('userGroups.removeLabel', { username: item.username })"
            color="error"
            size="small"
            @click="remove(item)"
          >
            {{ t('userGroups.remove') }}
          </v-btn>
        </template>
      </DataList>
    </template>

    <v-dialog
      v-model="renameOpen"
      max-width="32rem"
      :aria-label="t('userGroups.rename')"
    >
      <v-card :title="t('userGroups.rename')">
        <v-card-text>
          <form
            class="form"
            novalidate
            @submit.prevent="rename"
          >
            <v-text-field
              id="rename-group"
              v-model="newName"
              :label="t('common.name')"
              autocomplete="off"
            />
            <div class="form-actions">
              <v-btn
                type="button"
                variant="tonal"
                @click="renameOpen = false"
              >
                {{ t('common.cancel') }}
              </v-btn>
              <v-btn
                type="submit"
                color="primary"
              >
                {{ t('common.save') }}
              </v-btn>
            </div>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
