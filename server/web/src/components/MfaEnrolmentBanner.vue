<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatDateTime } from '../lib/format'
import { useSessionStore } from '../stores/session'

/**
 * The announcement of the second-factor change (ADR 0053 decision 6): shown to every administrator for 30 days after
 * the upgrade with the number of administrators who still have to set up a passkey. Dismissing it is a per-viewer
 * convenience kept in browser storage; without storage it returns on the next page load.
 */
const { t, locale } = useI18n()
const session = useSessionStore()
const storageKey = 'paddock.mfaEnrolmentNotice.dismissed'

function storedDismissal(): string | null {
  try {
    return localStorage.getItem(storageKey)
  } catch {
    return null
  }
}

const dismissedUntil = ref(storedDismissal())
const notice = computed(() => session.me?.mfa_enrolment_notice ?? null)
// A dismissal holds for the announcement it was given for: a later announcement (another until) shows again.
const visible = computed(() => notice.value !== null && dismissedUntil.value !== notice.value.until)

function dismiss(): void {
  if (!notice.value) return
  dismissedUntil.value = notice.value.until
  try {
    localStorage.setItem(storageKey, notice.value.until)
  } catch {
    // Not persisted; the notice stays hidden until the page is reloaded.
  }
}
</script>

<template>
  <v-alert
    v-if="visible && notice"
    type="info"
    variant="tonal"
    rounded="0"
    closable
    :close-label="t('app.mfaEnrolmentNoticeDismiss')"
    data-testid="mfa-enrolment-notice"
    @click:close="dismiss"
  >
    {{ t('app.mfaEnrolmentNotice', { pending: notice.pending, until: formatDateTime(notice.until, locale) }) }}
  </v-alert>
</template>
