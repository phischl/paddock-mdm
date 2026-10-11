<script setup lang="ts">
import { ref } from 'vue'
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
import { useSessionStore } from '../stores/session'

const { t } = useI18n()
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

async function onCreate(input: ProfileInput): Promise<void> {
  // Full rights are high-risk: typed confirmation (step-up follows in M4).
  if (input.class === 'full') {
    const confirmed = await confirm({
      title: t('profiles.fullTitle'), message: t('profiles.fullConfirm', { name: input.name }),
      confirmLabel: t('common.create'), destructive: true, requireTypedText: input.name.trim(),
    })
    if (!confirmed) return
  }
  const res = await createProfile(input)
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  open.value = false
  await router.push({ name: 'permission-profile', params: { id: res.id } })
}
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
            @submit="onCreate"
            @cancel="open = false"
          />
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>
