<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { User, UserRef } from '../api/client'
import { usePending } from '../composables/usePending'
import { setDeviceOwners } from '../lib/devices'
import { useProblemText } from '../lib/problems'
import { allUsers } from '../lib/users'

/**
 * The Owners panel of a device (plan M8d decision 5): writers pick users and save; readers see the owners as chips
 * that link to the users. Owners carry no login or sudo rights.
 */
const props = defineProps<{ deviceId: string; owners: UserRef[]; canWrite: boolean }>()
const emit = defineEmits<{ saved: [] }>()
const { t } = useI18n()
const { pending, run } = usePending()
const problemText = useProblemText()
const users = ref<User[]>([])
const selected = ref<string[]>(props.owners.map((o) => o.id))
const saved = ref(false)
const problem = ref('')

watch(
  () => props.owners,
  (owners) => {
    selected.value = owners.map((o) => o.id)
  },
)

onMounted(async () => {
  if (props.canWrite) users.value = await allUsers().catch(() => [])
})

async function save(): Promise<void> {
  saved.value = false
  problem.value = (await setDeviceOwners(props.deviceId, selected.value)) ?? ''
  if (problem.value) return
  saved.value = true
  emit('saved')
}
</script>

<template>
  <section
    class="pd-panel"
    aria-labelledby="device-owners-title"
    data-testid="device-owners"
  >
    <header class="pd-panel-header">
      <h2
        id="device-owners-title"
        class="pd-type-section"
      >
        {{ t('devices.owners.title') }}
      </h2>
    </header>
    <div class="pd-panel-body">
      <p class="pd-type-caption pd-muted">
        {{ t('devices.owners.hint') }}
      </p>
      <form
        v-if="canWrite"
        class="form"
        novalidate
        @submit.prevent="run(save)"
      >
        <v-autocomplete
          v-model="selected"
          :items="users.map((u) => ({ value: u.id, title: u.username }))"
          :label="t('devices.owners.title')"
          multiple
          chips
          closable-chips
          class="pd-chip-field"
          data-testid="device-owners-select"
        />
        <p
          v-if="problem"
          class="form-error"
          role="alert"
        >
          {{ problemText(problem) }}
        </p>
        <div class="form-actions">
          <span
            v-if="saved"
            role="status"
          >{{ t('devices.owners.saved') }}</span>
          <v-btn
            type="submit"
            :loading="pending"
            :disabled="pending"
            color="primary"
            data-testid="save-device-owners"
          >
            {{ t('common.save') }}
          </v-btn>
        </div>
      </form>
      <p
        v-if="owners.length === 0"
        class="pd-muted"
        data-testid="device-owners-none"
      >
        {{ t('devices.owners.none') }}
      </p>
      <p v-else>
        <RouterLink
          v-for="o in owners"
          :key="o.id"
          :to="{ name: 'user', params: { id: o.id } }"
          class="chip-link"
        >
          {{ o.username }}
        </RouterLink>
      </p>
    </div>
  </section>
</template>
