<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import EffectiveProfileView from '../components/EffectiveProfileView.vue'
import type { UserDetail, UserEffectiveProfile, UserGroup } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { allDevices } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import { useProblemText } from '../lib/problems'
import { allUserGroups } from '../lib/userGroups'
import { deleteUser, getEffectiveProfile, getUser, setLocked, updateUser } from '../lib/users'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const id = computed(() => String(route.params.id))

const user = ref<UserDetail | null>(null)
const problem = ref('')
const devices = ref<{ id: string; hostname: string }[]>([])
const groups = ref<UserGroup[]>([])
const deviceID = ref<string | null>(null)
const effective = ref<UserEffectiveProfile | null>(null)
const editOpen = ref(false)
const editName = ref('')
const editEmail = ref('')
const editProblem = ref('')

async function load(): Promise<void> {
  const u = await getUser(id.value)
  if (typeof u === 'string') {
    problem.value = u
    return
  }
  user.value = u
}

async function loadEffective(): Promise<void> {
  const e = await getEffectiveProfile(id.value, deviceID.value)
  effective.value = typeof e === 'string' ? null : e
}

onMounted(async () => {
  await load()
  const [d, g] = await Promise.all([allDevices(), allUserGroups()])
  devices.value = d
  groups.value = g
  await loadEffective()
})
watch(deviceID, () => void loadEffective())

function subjectName(type: string, subject: string | null): string {
  if (type === 'global') return t('profiles.subjectTypes.global')
  if (type === 'user') return user.value?.username ?? subject ?? ''
  return groups.value.find((g) => g.id === subject)?.name ?? subject ?? ''
}

async function toggleLock(): Promise<void> {
  if (!user.value) return
  const u = user.value
  const lock = !u.locked
  const confirmed = await confirm(
    lock
      ? {
          title: t('users.lockTitle'), message: t('users.lockConfirm', { username: u.username }),
          confirmLabel: t('users.lock'), destructive: true, requireTypedText: u.username,
        }
      : { title: t('users.unlockTitle'), message: t('users.unlockConfirm', { username: u.username }), confirmLabel: t('users.unlock') },
  )
  if (!confirmed) return
  problem.value = (await setLocked(u.id, lock)) ?? ''
  await load()
}

async function onDelete(): Promise<void> {
  if (!user.value) return
  const u = user.value
  const confirmed = await confirm({
    title: t('users.deleteTitle'), message: t('users.deleteConfirm', { username: u.username }),
    confirmLabel: t('common.delete'), destructive: true, requireTypedText: u.username,
  })
  if (!confirmed) return
  problem.value = (await deleteUser(u.id)) ?? ''
  if (!problem.value) await router.push({ name: 'users' })
}

function openEdit(): void {
  if (!user.value) return
  editName.value = user.value.display_name
  editEmail.value = user.value.email
  editProblem.value = ''
  editOpen.value = true
}

async function saveEdit(): Promise<void> {
  editProblem.value = (await updateUser(id.value, editName.value, editEmail.value)) ?? ''
  if (!editProblem.value) {
    editOpen.value = false
    await load()
  }
}
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'users' }">
        {{ t('users.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="user">
      <div class="page-header">
        <h1>{{ user.username }}</h1>
        <div class="row-actions">
          <v-btn
            v-if="session.canWrite && user.source === 'local'"
            variant="tonal"
            data-testid="edit-user"
            @click="openEdit"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            v-if="session.canDelete"
            :color="user.locked ? 'primary' : 'error'"
            data-testid="lock-user"
            @click="toggleLock"
          >
            {{ t(user.locked ? 'users.unlock' : 'users.lock') }}
          </v-btn>
          <v-btn
            v-if="session.canDelete && user.source === 'local'"
            color="error"
            variant="outlined"
            data-testid="delete-user"
            @click="onDelete"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </div>
      <v-alert
        v-if="user.source === 'synced'"
        type="info"
        variant="tonal"
        class="conflict"
      >
        {{ t('users.syncedHint') }}
      </v-alert>
      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('users.displayName') }}
            </th>
            <td>{{ user.display_name || '–' }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('users.email') }}
            </th>
            <td>{{ user.email || '–' }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('users.source') }}
            </th>
            <td>{{ t('users.sources.' + user.source) }}</td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('users.lockState') }}
            </th>
            <td data-testid="user-lock-state">
              {{ user.locked && user.locked_at ? t('users.lockedSince', { at: formatDateTime(user.locked_at, locale) }) : t('users.notLocked') }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('users.groups') }}
            </th>
            <td>
              <template v-if="user.groups.length === 0">
                –
              </template>
              <RouterLink
                v-for="g in user.groups"
                :key="g.id"
                :to="{ name: 'user-group', params: { id: g.id } }"
                class="chip-link"
              >
                {{ g.name }}
              </RouterLink>
            </td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('profiles.effectiveTitle') }}</h2>
      <v-autocomplete
        v-model="deviceID"
        :items="[{ value: null, title: t('profiles.noDevice') }, ...devices.map((d) => ({ value: d.id, title: d.hostname }))]"
        :label="t('profiles.onDevice')"
        data-testid="effective-device"
      />
      <EffectiveProfileView
        v-if="effective"
        :profile="effective"
        :subject-name="subjectName"
      />
    </template>

    <v-dialog
      v-model="editOpen"
      max-width="32rem"
      :aria-label="t('users.editTitle')"
    >
      <v-card :title="t('users.editTitle')">
        <v-card-text>
          <form
            class="form"
            novalidate
            @submit.prevent="saveEdit"
          >
            <v-text-field
              id="edit-user-name"
              v-model="editName"
              :label="t('users.displayName')"
              autocomplete="off"
            />
            <v-text-field
              id="edit-user-email"
              v-model="editEmail"
              :label="t('users.email')"
              type="email"
              autocomplete="off"
            />
            <p
              v-if="editProblem"
              class="form-error"
              role="alert"
            >
              {{ problemText(editProblem) }}
            </p>
            <div class="form-actions">
              <v-btn
                type="button"
                variant="tonal"
                @click="editOpen = false"
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
