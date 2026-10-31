<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Account, Finding } from '../api/client'
import { listAccounts } from '../lib/findings'
import { useProblemText } from '../lib/problems'

/**
 * Assigns a finding to an administrator or operator of the organization, or removes the assignee (plan M9
 * decision 35). The accounts come from the account list; the choice is searched in the loaded accounts.
 */
const props = defineProps<{
  modelValue: boolean
  finding: Finding | null
  problem: string
  pending: boolean
}>()
const emit = defineEmits<{
  submit: [assigneeID: string | null]
  cancel: []
}>()

const { t } = useI18n()
const problemText = useProblemText()
const accounts = ref<Account[]>([])
const assignee = ref<string | null>(props.finding?.assignee?.id ?? null)

onMounted(async () => {
  accounts.value = await listAccounts()
})

function title(a: Account): string {
  return a.display_name && a.display_name !== a.username ? `${a.display_name} (${a.username})` : a.username
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="32rem"
    :aria-label="t('findings.assign.title')"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
  >
    <v-card
      :title="t('findings.assign.title')"
      data-testid="finding-assign-dialog"
    >
      <v-card-text>
        <p>{{ t('findings.assign.message', { code: finding?.code ?? '', hostname: finding?.hostname ?? '' }) }}</p>
        <v-autocomplete
          v-model="assignee"
          :items="accounts"
          :item-title="title"
          item-value="id"
          :label="t('findings.assign.assignee')"
          :hint="t('findings.assign.hint')"
          persistent-hint
          clearable
          autocomplete="off"
          data-testid="finding-assignee"
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
            variant="tonal"
            data-testid="finding-assign-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="primary"
            variant="flat"
            :loading="pending"
            :disabled="pending"
            data-testid="finding-assign-submit"
            @click="emit('submit', assignee)"
          >
            {{ assignee ? t('findings.assign.submit') : t('findings.assign.unassign') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
