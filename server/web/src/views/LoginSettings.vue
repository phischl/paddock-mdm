<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SessionAction } from '../api/client'
import { formatDateTime } from '../lib/format'
import { getLoginSettings, lines, saveLoginSettings } from '../lib/loginSettings'
import { useProblemText } from '../lib/problems'
import { useSessionStore } from '../stores/session'

const { t, locale } = useI18n()
const problemText = useProblemText()
const session = useSessionStore()
const sessionActions: SessionAction[] = ['lock_screen', 'terminate']

const loaded = ref(false)
const helloEnabled = ref(true)
const pinLength = ref('6')
const sessionAction = ref<SessionAction>('lock_screen')
const breakGlass = ref('')
const allowlist = ref('')
const lecture = ref('')
const localAdmin = ref('')
const rotationDays = ref('30')
const revealHours = ref('')
const notice = ref('')
const updatedAt = ref('')
const problem = ref('')
const saved = ref(false)

function apply(s: Exclude<Awaited<ReturnType<typeof getLoginSettings>>, string>): void {
  helloEnabled.value = s.hello_enabled
  pinLength.value = String(s.hello_pin_min_length)
  sessionAction.value = s.user_lock_session_action
  breakGlass.value = s.break_glass_accounts.join('\n')
  allowlist.value = s.sudoers_d_allowlist.join('\n')
  lecture.value = s.sudo_lecture_text
  localAdmin.value = s.local_admin_username
  rotationDays.value = String(s.local_admin_rotation_days)
  revealHours.value = s.rotate_after_reveal_hours === null ? '' : String(s.rotate_after_reveal_hours)
  notice.value = s.notice_text
  updatedAt.value = s.updated_at
  loaded.value = true
}

onMounted(async () => {
  const s = await getLoginSettings()
  if (typeof s === 'string') problem.value = s
  else apply(s)
})

async function save(): Promise<void> {
  problem.value = ''
  saved.value = false
  const res = await saveLoginSettings({
    hello_enabled: helloEnabled.value, hello_pin_min_length: Number(pinLength.value),
    user_lock_session_action: sessionAction.value, break_glass_accounts: lines(breakGlass.value),
    sudoers_d_allowlist: lines(allowlist.value), sudo_lecture_text: lecture.value.trim(),
    local_admin_username: localAdmin.value.trim(), local_admin_rotation_days: Number(rotationDays.value),
    rotate_after_reveal_hours: revealHours.value.trim() === '' ? null : Number(revealHours.value),
    notice_text: notice.value.trim(),
  })
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}
</script>

<template>
  <section class="page">
    <h1>{{ t('loginSettings.title') }}</h1>
    <p
      v-if="updatedAt"
      class="summary"
    >
      {{ t('loginSettings.updatedAt', { at: formatDateTime(updatedAt, locale) }) }}
    </p>
    <form
      v-if="loaded"
      class="form settings-form"
      novalidate
      @submit.prevent="save"
    >
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('loginSettings.login') }}</legend>
        <v-switch
          id="settings-hello"
          v-model="helloEnabled"
          :label="t('loginSettings.helloEnabled')"
          color="primary"
          inset
        />
        <v-text-field
          id="settings-pin"
          v-model="pinLength"
          :label="t('loginSettings.pinLength')"
          type="number"
          min="6"
          max="32"
        />
        <v-select
          id="settings-session-action"
          v-model="sessionAction"
          :label="t('loginSettings.sessionAction')"
          :items="sessionActions.map((a) => ({ value: a, title: t('loginSettings.sessionActions.' + a) }))"
          :hint="t('loginSettings.sessionActionHint')"
          persistent-hint
        />
        <v-textarea
          id="settings-break-glass"
          v-model="breakGlass"
          :label="t('loginSettings.breakGlass')"
          :hint="t('loginSettings.breakGlassHint')"
          persistent-hint
          rows="2"
        />
        <v-textarea
          id="settings-notice"
          v-model="notice"
          :label="t('loginSettings.notice')"
          :hint="t('loginSettings.noticeHint')"
          persistent-hint
          rows="4"
          counter="2000"
        />
      </fieldset>
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('loginSettings.privileges') }}</legend>
        <v-textarea
          id="settings-allowlist"
          v-model="allowlist"
          :label="t('loginSettings.allowlist')"
          :hint="t('loginSettings.allowlistHint')"
          persistent-hint
          rows="2"
        />
        <v-textarea
          id="settings-lecture"
          v-model="lecture"
          :label="t('loginSettings.lecture')"
          :hint="t('loginSettings.lectureHint')"
          persistent-hint
          rows="4"
          counter="2000"
        />
      </fieldset>
      <fieldset :disabled="!session.canDelete">
        <legend>{{ t('loginSettings.localAdmin') }}</legend>
        <v-text-field
          id="settings-local-admin"
          v-model="localAdmin"
          :label="t('loginSettings.localAdminUsername')"
          :hint="t('loginSettings.localAdminUsernameHint')"
          persistent-hint
        />
        <v-text-field
          id="settings-rotation-days"
          v-model="rotationDays"
          :label="t('loginSettings.rotationDays')"
          type="number"
          min="1"
          max="365"
        />
        <v-text-field
          id="settings-reveal-hours"
          v-model="revealHours"
          :label="t('loginSettings.rotateAfterReveal')"
          :hint="t('loginSettings.rotateAfterRevealHint')"
          persistent-hint
          type="number"
          min="1"
          max="168"
        />
      </fieldset>
      <p
        v-if="problem"
        class="form-error"
        role="alert"
      >
        {{ problemText(problem) }}
      </p>
      <div
        v-if="session.canDelete"
        class="form-actions"
      >
        <span
          v-if="saved"
          role="status"
        >{{ t('loginSettings.saved') }}</span>
        <v-btn
          type="submit"
          color="primary"
          data-testid="save-login-settings"
        >
          {{ t('common.save') }}
        </v-btn>
      </div>
    </form>
    <p
      v-else-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
  </section>
</template>
