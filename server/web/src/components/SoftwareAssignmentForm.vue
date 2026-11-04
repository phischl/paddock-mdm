<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SoftwareAssignment, SoftwareIntent, SoftwareUpdateRule } from '../api/client'
import { useProblemText } from '../lib/problems'
import {
  softwareIntents, updateRuleEnabled, validateAssignment, versionEnabled, type AssignmentInput,
} from '../lib/software'
import { hasErrors } from '../lib/validation'

/**
 * Create and edit form of an assignment: scope, intent, update rule, version and reason. The update rule and the
 * version follow the rules of plan M13a decision 9; a field the intent does not allow is disabled and sent empty.
 */
const props = withDefaults(
  defineProps<{ entryId: string; groups: { id: string; name: string }[]; initial?: SoftwareAssignment | null; problem?: string; pending?: boolean }>(),
  { initial: null, problem: '', pending: false },
)
const emit = defineEmits<{ submit: [input: AssignmentInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const groupID = ref<string | null>(props.initial?.device_group_id ?? null)
const intent = ref<SoftwareIntent>(props.initial?.intent ?? 'required')
const updateRule = ref<SoftwareUpdateRule>(props.initial?.update_rule ?? 'latest')
const version = ref(props.initial?.version ?? '')
const reason = ref(props.initial?.reason ?? '')
const touched = ref(false)

const ruleEnabled = computed(() => updateRuleEnabled(intent.value))
const versionOn = computed(() => versionEnabled(intent.value, ruleEnabled.value ? updateRule.value : 'latest'))
const input = computed<AssignmentInput>(() => ({
  entryID: props.entryId, groupID: groupID.value, intent: intent.value, updateRule: updateRule.value, version: version.value, reason: reason.value,
}))
const errors = computed(() => validateAssignment(input.value))

watch(versionOn, (on) => {
  if (!on) version.value = ''
})

function submit(): void {
  touched.value = true
  if (hasErrors(errors.value)) return
  emit('submit', input.value)
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-autocomplete
      id="assignment-scope"
      v-model="groupID"
      :label="t('managed.scope')"
      :items="[{ value: null, title: t('managed.allDevices') }, ...props.groups.map((g) => ({ value: g.id, title: g.name }))]"
      :disabled="initial !== null"
      data-testid="assignment-scope"
    />
    <v-select
      id="assignment-intent"
      v-model="intent"
      :label="t('software.assignments.intent')"
      :items="softwareIntents.map((value) => ({ value, title: t('software.intent.' + value) }))"
      data-testid="assignment-intent"
    />
    <v-select
      id="assignment-rule"
      v-model="updateRule"
      :label="t('software.assignments.updateRule')"
      :items="(['latest', 'pinned'] as const).map((value) => ({ value, title: t('software.updateRule.' + value) }))"
      :disabled="!ruleEnabled"
      data-testid="assignment-rule"
    />
    <v-text-field
      id="assignment-version"
      v-model="version"
      :label="t('software.assignments.version')"
      :hint="t(intent === 'hold' ? 'software.assignments.versionHintHold' : 'software.assignments.versionHint')"
      persistent-hint
      autocomplete="off"
      spellcheck="false"
      :disabled="!versionOn"
      :error-messages="touched && errors.version ? [t(errors.version)] : []"
      data-testid="assignment-version"
    />
    <v-textarea
      id="assignment-reason"
      v-model="reason"
      :label="t('software.assignments.reason')"
      rows="2"
      auto-grow
      counter="500"
      :error-messages="touched && errors.reason ? [t(errors.reason)] : []"
      data-testid="assignment-reason"
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
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </v-btn>
      <v-btn
        type="submit"
        color="primary"
        :loading="pending"
        :disabled="pending"
        data-testid="save-assignment"
      >
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>
