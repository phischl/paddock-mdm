<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import DataList from '../components/DataList.vue'
import StatusChip from '../components/StatusChip.vue'
import TimeCell from '../components/TimeCell.vue'
import ProfileForm from '../components/ProfileForm.vue'
import type { PermissionProfile } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import type { ListColumn } from '../lib/listQuery'
import { classFilter, createProfile, listProfiles, type ProfileInput } from '../lib/profiles'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

const { t } = useI18n()
const { pending, run } = usePending()
const router = useRouter()
const confirm = useConfirm()
const session = useSessionStore()
const open = ref(false)
const problem = ref('')

const columns: ListColumn[] = [
  { key: 'name', title: 'common.name', sortable: true },
  { key: 'class', title: 'profiles.class', sortable: true },
  { key: 'commands', title: 'profiles.commands' },
  { key: 'updated_at', title: 'common.updatedAt', sortable: true },
]

/** Full rights are high-risk: the typed name confirms them, for class full before and for a root-equivalent
 * restricted profile when the server asks for the step-up (ADR 0034 decision 1). */
async function confirmRoot(input: ProfileInput, message: string): Promise<boolean> {
  return confirm({
    title: t('profiles.fullTitle'), message, confirmLabel: t('common.create'), destructive: true,
    requireTypedText: input.name.trim(),
  })
}

async function create(input: ProfileInput): Promise<string> {
  const res = await createProfile(input)
  if (typeof res === 'string') return res
  open.value = false
  await router.push({ name: 'permission-profile', params: { id: res.id } })
  return ''
}

async function onCreate(input: ProfileInput): Promise<void> {
  if (input.class === 'full' && !(await confirmRoot(input, t('profiles.fullConfirm', { name: input.name })))) return
  problem.value = await create(input)
  if (problem.value !== stepUpRequired) return
  if (input.class !== 'full' && !(await confirmRoot(input, t('profiles.rootGrantConfirm', { name: input.name })))) return
  startStepUp('profile-create', 'new', input)
}

/** A creation the server refused with step_up_required is repeated once after the step-up. */
onMounted(async () => {
  const pending = resumeStepUp<ProfileInput>('profile-create', 'new')
  if (!pending) return
  await router.replace(withoutStepUpParam())
  problem.value = pending.failed ? 'step_up_failed' : await create(pending.payload)
  if (problem.value) open.value = true
})
</script>

<template>
  <section class="page">
    <div class="page-header">
      <h1>{{ t('profiles.title') }}</h1>
      <v-btn
        v-if="session.canWrite"
        color="primary"
        data-testid="create-profile"
        @click="problem = ''; open = true"
      >
        {{ t('profiles.create') }}
      </v-btn>
    </div>
    <DataList
      :columns="columns"
      :fetch="listProfiles"
      :filters="[classFilter]"
      searchable
      default-sort="name"
      item-value="id"
      empty-icon="shield-check"
      empty-title="profiles.empty.title"
      empty-description="profiles.empty.description"
      data-testid="profile-list"
    >
      <template #empty-action>
        <v-btn
          v-if="session.canWrite"
          color="primary"
          @click="problem = ''; open = true"
        >
          {{ t('profiles.create') }}
        </v-btn>
      </template>
      <template #[`item.name`]="{ item }: { item: PermissionProfile }">
        <RouterLink :to="{ name: 'permission-profile', params: { id: item.id } }">
          {{ item.name }}
        </RouterLink>
      </template>
      <template #[`item.class`]="{ item }: { item: PermissionProfile }">
        {{ t('profiles.classes.' + item.class) }}
        <StatusChip
          v-if="item.effective_class !== item.class"
          status="warn"
          :label="t('privileges.effectiveClass.' + item.effective_class)"
          data-testid="profile-effective-class"
        />
        <StatusChip
          v-if="item.root_equivalent"
          status="warn"
          :label="t('profiles.rootEquivalentBadge')"
        />
        <StatusChip
          v-if="item.invalid_commands.length > 0"
          status="critical"
          :label="t('profiles.invalidBadge')"
          data-testid="profile-invalid"
        />
      </template>
      <template #[`item.commands`]="{ item }: { item: PermissionProfile }">
        {{ t('profiles.commandCount', { count: item.commands.length }) }}
      </template>
      <template #[`item.updated_at`]="{ item }: { item: PermissionProfile }">
        <TimeCell :iso="item.updated_at" />
      </template>
    </DataList>

    <v-dialog
      v-model="open"
      max-width="40rem"
      :aria-label="t('profiles.createTitle')"
    >
      <v-card :title="t('profiles.createTitle')">
        <v-card-text>
          <ProfileForm
            id-prefix="create-profile"
            :submit-label="t('common.create')"
            :problem="problem"
            :pending="pending"
            @submit="run(() => onCreate($event))"
            @cancel="open = false"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
