<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { auditCodes } from '../lib/auditCodes.gen'
import {
  emptyInput, fieldOfProblem, inputOf, parseRecipients, validateNotification, type NotificationDestination,
  type NotificationErrors, type NotificationField, type NotificationInput, type NotificationProblem, type NotificationScope,
} from '../lib/notifications'
import { useProblemText } from '../lib/problems'

const props = withDefaults(defineProps<{
  scope: NotificationScope
  /** The destination being edited; null creates a new one. */
  initial?: NotificationDestination | null
  emailAvailable: boolean
  problem?: NotificationProblem | null
  pending?: boolean
  /** The values to start from, e.g. after a step-up; the URL is never part of them. */
  restored?: NotificationInput | null
}>(), { initial: null, problem: null, pending: false, restored: null })
const emit = defineEmits<{ submit: [input: NotificationInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const form = reactive<NotificationInput>(props.restored ? { ...props.restored } : props.initial ? inputOf(props.initial) : emptyInput())
const recipientsText = ref(form.recipients.join('\n'))
const touched = ref(false)
const editing = computed(() => props.initial !== null)
const clientErrors = computed<NotificationErrors>(() => {
  if (!touched.value) return {}
  return validateNotification({ ...form, recipients: parseRecipients(recipientsText.value) }, editing.value, auditCodes)
})

const serverField = computed<NotificationField | null>(() => (props.problem ? fieldOfProblem(props.problem) : null))
const serverMessage = computed(() => {
  if (!props.problem) return ''
  return problemText(props.problem.code) + (props.problem.detail ? ' (' + props.problem.detail + ')' : '')
})

/** The messages of a field: its own validation first, else the server's problem when it belongs to the field. */
function errorsOf(field: NotificationField): string[] {
  const own = clientErrors.value[field]
  if (own) return [t(own)]
  return serverField.value === field && serverMessage.value ? [serverMessage.value] : []
}

const typeOptions = computed(() => [
  { value: 'webhook', title: t('notifications.types.webhook') },
  ...(props.emailAvailable || form.type === 'email' ? [{ value: 'email', title: t('notifications.types.email') }] : []),
])
const modeOptions = computed(() =>
  (['security', 'all', 'custom'] as const).map((value) => ({ value, title: t('notifications.modes.' + value) })),
)

function submit(): void {
  touched.value = true
  form.recipients = parseRecipients(recipientsText.value)
  if (Object.keys(validateNotification(form, editing.value, auditCodes)).length > 0) return
  emit('submit', { ...form, recipients: [...form.recipients], codes: [...form.codes] })
}
</script>

<template>
  <form
    class="form"
    novalidate
    data-testid="notification-form"
    @submit.prevent="submit"
  >
    <v-radio-group
      v-model="form.type"
      :label="t('notifications.type')"
      :disabled="editing"
      :error-messages="errorsOf('type')"
      inline
      data-testid="notification-type"
    >
      <v-radio
        v-for="o in typeOptions"
        :key="o.value"
        :label="o.title"
        :value="o.value"
        :data-testid="'notification-type-' + o.value"
      />
    </v-radio-group>
    <v-text-field
      id="notification-name"
      v-model="form.name"
      :label="t('common.name')"
      autocomplete="off"
      :hint="t('notifications.nameHint')"
      :error-messages="errorsOf('name')"
    />
    <v-text-field
      v-if="form.type === 'webhook'"
      id="notification-url"
      v-model="form.url"
      :label="t('notifications.url')"
      :placeholder="editing ? t('notifications.urlUnchanged') : 'https://'"
      :hint="editing && initial?.url_display ? t('notifications.urlCurrent', { url: initial.url_display }) : t('notifications.urlHint')"
      persistent-hint
      type="url"
      autocomplete="off"
      spellcheck="false"
      :error-messages="errorsOf('url')"
    />
    <v-textarea
      v-else
      id="notification-recipients"
      v-model="recipientsText"
      :label="t('notifications.recipients')"
      :hint="t('notifications.recipientsHint')"
      persistent-hint
      rows="3"
      auto-grow
      autocomplete="off"
      :error-messages="errorsOf('recipients')"
    />
    <v-select
      id="notification-filter-mode"
      v-model="form.filterMode"
      :label="t('notifications.filterMode')"
      :items="modeOptions"
      item-title="title"
      item-value="value"
      :hint="t('notifications.modeHints.' + form.filterMode)"
      persistent-hint
    />
    <v-combobox
      v-if="form.filterMode === 'custom'"
      id="notification-codes"
      v-model="form.codes"
      :label="t('notifications.codes')"
      :items="[...auditCodes]"
      :hint="t('notifications.codesHint')"
      persistent-hint
      multiple
      chips
      closable-chips
      :error-messages="errorsOf('codes')"
      data-testid="notification-codes"
    />
    <v-switch
      v-if="scope === 'organization'"
      v-model="form.pseudonymizeUsers"
      :label="t('notifications.pseudonymize')"
      color="primary"
      inset
      hide-details
      data-testid="notification-pseudonymize"
    />
    <v-switch
      v-model="form.includeParams"
      :label="t('notifications.includeParams')"
      color="primary"
      inset
      hide-details
      data-testid="notification-include-params"
    />
    <v-text-field
      v-if="form.type === 'webhook'"
      id="notification-heartbeat"
      v-model.number="form.heartbeatIntervalS"
      :label="t('notifications.heartbeat')"
      :hint="t('notifications.heartbeatHint')"
      persistent-hint
      type="number"
      :error-messages="errorsOf('heartbeat')"
    />
    <v-text-field
      v-else
      id="notification-interval"
      v-model.number="form.emailMinIntervalS"
      :label="t('notifications.minInterval')"
      :hint="t('notifications.minIntervalHint')"
      persistent-hint
      type="number"
      :error-messages="errorsOf('interval')"
    />
    <v-switch
      v-model="form.enabled"
      :label="t('notifications.enabled')"
      color="primary"
      inset
      hide-details
      data-testid="notification-enabled"
    />
    <p
      v-if="problem && !serverField"
      class="form-error"
      role="alert"
      data-testid="notification-problem"
    >
      {{ serverMessage }}
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
        :loading="pending"
        :disabled="pending"
        color="primary"
        data-testid="notification-submit"
      >
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>
