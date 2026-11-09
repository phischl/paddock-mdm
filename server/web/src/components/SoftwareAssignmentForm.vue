<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SoftwareAssignment, SoftwareIntent, SoftwareTarget, SoftwareUpdateRule } from '../api/client'
import { useProblemText } from '../lib/problems'
import {
  assignmentTarget, softwareIntents, softwareTargets, updateRuleEnabled, validateAssignment, versionEnabled, type AssignmentInput,
} from '../lib/software'
import { hasErrors } from '../lib/validation'

/**
 * Create and edit form of an assignment: target, intent, update rule, version and reason. The target is the whole
 * organization, one device group, one user or one user group (plan M13b decision 1); the pickers search the names. The
 * update rule and the version follow the rules of plan M13a decision 9; a field the intent does not allow is disabled
 * and sent empty. The target of a stored assignment is fixed.
 */
const props = withDefaults(
  defineProps<{
    entryId: string
    groups: { id: string; name: string }[]
    users: { id: string; username: string }[]
    userGroups: { id: string; name: string }[]
    initial?: SoftwareAssignment | null
    problem?: string
    pending?: boolean
  }>(),
  { initial: null, problem: '', pending: false },
)
const emit = defineEmits<{ submit: [input: AssignmentInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const stored = props.initial ? assignmentTarget(props.initial) : { target: 'organization' as SoftwareTarget, targetID: null }
const target = ref<SoftwareTarget>(stored.target)
const targetID = ref<string | null>(stored.targetID)
const intent = ref<SoftwareIntent>(props.initial?.intent ?? 'required')
const updateRule = ref<SoftwareUpdateRule>(props.initial?.update_rule ?? 'latest')
const version = ref(props.initial?.version ?? '')
const reason = ref(props.initial?.reason ?? '')
const touched = ref(false)

const ruleEnabled = computed(() => updateRuleEnabled(intent.value))
const versionOn = computed(() => versionEnabled(intent.value, ruleEnabled.value ? updateRule.value : 'latest'))
const input = computed<AssignmentInput>(() => ({
  entryID: props.entryId, target: target.value, targetID: target.value === 'organization' ? null : targetID.value,
  intent: intent.value, updateRule: updateRule.value, version: version.value, reason: reason.value,
}))
const errors = computed(() => validateAssignment(input.value))
const targetItems = computed(() => {
  switch (target.value) {
    case 'device_group':
      return props.groups.map((g) => ({ value: g.id, title: g.name }))
    case 'user':
      return props.users.map((u) => ({ value: u.id, title: u.username }))
    case 'user_group':
      return props.userGroups.map((g) => ({ value: g.id, title: g.name }))
    default:
      return []
  }
})

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
    <v-select
      id="assignment-target"
      v-model="target"
      :label="t('software.assignments.target')"
      :items="softwareTargets.map((value) => ({ value, title: t('software.target.' + value) }))"
      :disabled="initial !== null"
      data-testid="assignment-target"
      @update:model-value="targetID = null"
    />
    <v-autocomplete
      v-if="target !== 'organization'"
      id="assignment-target-id"
      v-model="targetID"
      :label="t('software.target.' + target)"
      :items="targetItems"
      :disabled="initial !== null"
      :error-messages="touched && errors.target ? [t(errors.target)] : []"
      data-testid="assignment-target-id"
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
