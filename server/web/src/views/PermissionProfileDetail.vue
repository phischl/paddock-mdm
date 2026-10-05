<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DataList from '../components/DataList.vue'
import ProfileForm from '../components/ProfileForm.vue'
import type { PermissionProfile, ProfileAssignment, SubjectType, User, UserGroup } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { allGroups } from '../lib/devices'
import { formatDateTime } from '../lib/format'
import type { ListColumn } from '../lib/listQuery'
import { useProblemText } from '../lib/problems'
import {
  createAssignment, deleteAssignment, deleteProfile, getProfile, listAssignments, subjectTypeFilter, subjectTypes,
  updateProfile, type ProfileInput,
} from '../lib/profiles'
import { allUserGroups } from '../lib/userGroups'
import { allUsers } from '../lib/users'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const id = computed(() => String(route.params.id))
const list = ref<{ reload: () => Promise<void> } | null>(null)

const profile = ref<PermissionProfile | null>(null)
const problem = ref('')
const editOpen = ref(false)
const editProblem = ref('')
const users = ref<User[]>([])
const groups = ref<UserGroup[]>([])
const deviceGroups = ref<{ id: string; name: string }[]>([])
const subjectType = ref<SubjectType>('group')
const subjectID = ref<string | null>(null)
const deviceGroupID = ref<string | null>(null)
const assignProblem = ref('')
const fetchAssignments = computed(() => listAssignments(id.value))

const columns = computed<ListColumn[]>(() => [
  { key: 'subject_type', title: 'profiles.subjectType', sortable: true },
  { key: 'subject_id', title: 'profiles.assignedTo' },
  { key: 'device_group_id', title: 'profiles.scope' },
  { key: 'created_at', title: 'common.createdAt', sortable: true },
  ...(session.canWrite ? [{ key: 'actions', title: 'common.actions' }] : []),
])
const subjects = computed(() =>
  subjectType.value === 'user'
    ? users.value.map((u) => ({ value: u.id, title: u.username }))
    : groups.value.map((g) => ({ value: g.id, title: g.name })),
)

async function load(): Promise<void> {
  const p = await getProfile(id.value)
  if (typeof p === 'string') {
    problem.value = p
    return
  }
  profile.value = p
}

onMounted(async () => {
  await load()
  const [u, g, d] = await Promise.all([allUsers(), allUserGroups(), allGroups()])
  users.value = u
  groups.value = g
  deviceGroups.value = d
})

function subjectName(a: ProfileAssignment): string {
  if (a.subject_type === 'global') return t('profiles.everyone')
  if (a.subject_type === 'user') return users.value.find((u) => u.id === a.subject_id)?.username ?? a.subject_id ?? ''
  return groups.value.find((g) => g.id === a.subject_id)?.name ?? a.subject_id ?? ''
}

function scopeName(deviceGroup: string | null | undefined): string {
  if (!deviceGroup) return t('managed.allDevices')
  return deviceGroups.value.find((g) => g.id === deviceGroup)?.name ?? deviceGroup
}

/** Full rights are high-risk: changing a profile to full or assigning a full profile needs the typed name. */
async function confirmFull(message: string, label: string): Promise<boolean> {
  if (!profile.value) return false
  return confirm({
    title: t('profiles.fullTitle'), message, confirmLabel: label, destructive: true, requireTypedText: profile.value.name,
  })
}

async function onEdit(input: ProfileInput): Promise<void> {
  if (!profile.value) return
  if (input.class === 'full' && profile.value.class !== 'full' &&
    !(await confirmFull(t('profiles.toFullConfirm', { name: profile.value.name }), t('common.save')))) {
    return
  }
  editProblem.value = (await updateProfile(id.value, input)) ?? ''
  if (!editProblem.value) {
    editOpen.value = false
    await load()
  }
}

async function onDelete(): Promise<void> {
  if (!profile.value) return
  const confirmed = await confirm({
    title: t('profiles.deleteTitle'), message: t('profiles.deleteConfirm', { name: profile.value.name }),
    confirmLabel: t('common.delete'), destructive: true,
  })
  if (!confirmed) return
  problem.value = (await deleteProfile(id.value)) ?? ''
  if (!problem.value) await router.push({ name: 'permission-profiles' })
}

async function assign(): Promise<void> {
  if (!profile.value) return
  assignProblem.value = ''
  if (subjectType.value !== 'global' && !subjectID.value) {
    assignProblem.value = 'invalid_request'
    return
  }
  if (profile.value.class === 'full' &&
    !(await confirmFull(t('profiles.assignFullConfirm', { name: profile.value.name }), t('profiles.assign')))) {
    return
  }
  assignProblem.value = (await createAssignment(id.value, {
    subjectType: subjectType.value, subjectID: subjectID.value, deviceGroupID: deviceGroupID.value,
  })) ?? ''
  if (!assignProblem.value) {
    subjectID.value = null
    void list.value?.reload()
  }
}

async function unassign(a: ProfileAssignment): Promise<void> {
  const confirmed = await confirm({
    title: t('profiles.unassignTitle'), message: t('profiles.unassignConfirm', { name: profile.value?.name ?? '', subject: subjectName(a) }),
    confirmLabel: t('profiles.unassign'), destructive: true,
  })
  if (!confirmed) return
  problem.value = (await deleteAssignment(a.id)) ?? ''
  void list.value?.reload()
}
</script>

<template>
  <section class="page">
    <p>
      <RouterLink :to="{ name: 'permission-profiles' }">
        {{ t('profiles.back') }}
      </RouterLink>
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="profile">
      <div class="page-header">
        <h1>{{ profile.name }}</h1>
        <div
          v-if="session.canWrite"
          class="row-actions"
        >
          <v-btn
            variant="tonal"
            data-testid="edit-profile"
            @click="editProblem = ''; editOpen = true"
          >
            {{ t('common.edit') }}
          </v-btn>
          <v-btn
            color="error"
            data-testid="delete-profile"
            @click="onDelete"
          >
            {{ t('common.delete') }}
          </v-btn>
        </div>
      </div>
      <v-alert
        v-if="profile.invalid_commands.length > 0"
        type="error"
        variant="tonal"
        class="conflict"
        data-testid="invalid-profile"
      >
        {{ t('profiles.invalidProfile', { commands: profile.invalid_commands.join(', ') }) }}
      </v-alert>
      <v-alert
        v-if="profile.root_equivalent"
        type="warning"
        variant="tonal"
        class="conflict"
        data-testid="root-equivalent-warning"
      >
        {{ t('profiles.rootEquivalentProfile', { commands: profile.root_equivalent_commands.join(', ') }) }}
      </v-alert>
      <v-table class="table facts">
        <tbody>
          <tr>
            <th scope="row">
              {{ t('profiles.class') }}
            </th>
            <td>{{ t('profiles.classes.' + profile.class) }}</td>
          </tr>
          <tr v-if="profile.class === 'restricted'">
            <th scope="row">
              {{ t('profiles.commands') }}
            </th>
            <td>
              <code
                v-for="c in profile.commands"
                :key="c"
                class="command"
              >{{ c }}</code>
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('profiles.scalars') }}
            </th>
            <td>
              {{ t('profiles.scalarFacts', { password: String(profile.require_password), timeout: profile.timestamp_timeout_min, lecture: t('profiles.lectures.' + profile.lecture) }) }}
            </td>
          </tr>
          <tr>
            <th scope="row">
              {{ t('common.updatedAt') }}
            </th>
            <td>{{ formatDateTime(profile.updated_at, locale) }}</td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('profiles.assignments') }}</h2>
      <form
        v-if="session.canWrite"
        class="form assign-form"
        novalidate
        @submit.prevent="assign"
      >
        <v-select
          v-model="subjectType"
          :items="subjectTypes.map((s) => ({ value: s, title: t('profiles.subjectTypes.' + s) }))"
          :label="t('profiles.subjectType')"
          data-testid="assign-subject-type"
          @update:model-value="subjectID = null"
        />
        <v-autocomplete
          v-if="subjectType !== 'global'"
          v-model="subjectID"
          :items="subjects"
          :label="t('profiles.assignedTo')"
          data-testid="assign-subject"
        />
        <v-autocomplete
          v-model="deviceGroupID"
          :items="[{ value: null, title: t('managed.allDevices') }, ...deviceGroups.map((g) => ({ value: g.id, title: g.name }))]"
          :label="t('profiles.scope')"
          data-testid="assign-scope"
        />
        <p
          v-if="assignProblem"
          class="form-error"
          role="alert"
        >
          {{ problemText(assignProblem) }}
        </p>
        <div class="form-actions">
          <v-btn
            type="submit"
            color="primary"
            data-testid="assign-submit"
          >
            {{ t('profiles.assign') }}
          </v-btn>
        </div>
      </form>
      <DataList
        ref="list"
        :columns="columns"
        :fetch="fetchAssignments"
        :filters="[subjectTypeFilter]"
        default-sort="created_at"
        item-value="id"
        data-testid="assignment-list"
      >
        <template #[`item.subject_type`]="{ item }: { item: ProfileAssignment }">
          {{ t('profiles.subjectTypes.' + item.subject_type) }}
        </template>
        <template #[`item.subject_id`]="{ item }: { item: ProfileAssignment }">
          {{ subjectName(item) }}
        </template>
        <template #[`item.device_group_id`]="{ item }: { item: ProfileAssignment }">
          {{ scopeName(item.device_group_id) }}
        </template>
        <template #[`item.created_at`]="{ item }: { item: ProfileAssignment }">
          {{ formatDateTime(item.created_at, locale) }}
        </template>
        <template #[`item.actions`]="{ item }: { item: ProfileAssignment }">
          <v-btn
            :aria-label="t('profiles.unassignLabel', { subject: subjectName(item) })"
            color="error"
            size="small"
            @click="unassign(item)"
          >
            {{ t('profiles.unassign') }}
          </v-btn>
        </template>
      </DataList>
    </template>

    <v-dialog
      v-model="editOpen"
      max-width="40rem"
      :aria-label="t('profiles.editTitle')"
    >
      <v-card :title="t('profiles.editTitle')">
        <v-card-text>
          <ProfileForm
            v-if="profile"
            :key="profile.updated_at"
            id-prefix="edit-profile"
            :initial="{
              name: profile.name, class: profile.class, commands: profile.commands, requirePassword: profile.require_password,
              timestampTimeoutMin: profile.timestamp_timeout_min, lecture: profile.lecture,
            }"
            :submit-label="t('common.save')"
            :problem="editProblem"
            @submit="onEdit"
            @cancel="editOpen = false"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
