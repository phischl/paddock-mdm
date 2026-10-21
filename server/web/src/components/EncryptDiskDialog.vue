<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ComponentPublicInstance } from 'vue'
import { formatDuration } from '../lib/disk'
import { reducedMotion } from '../lib/pageContext'

/**
 * The confirmation of an in-place encryption (plan M8e decision 24), laid out like ConfirmDialog: the explanation,
 * the backup acknowledgement as a required checkbox, what the user meets at the restart, the duration estimate, the
 * switch of the early-boot system where the device reports initramfs-tools (§14.4 decision 34), the reason and the
 * typed hostname. Focus starts on Cancel; Esc cancels; Enter in the fields never submits.
 */
const props = defineProps<{
  modelValue: boolean
  hostname: string
  tpmOnly: boolean
  /** The device's initramfs generator (health disk.conversion.initramfs). */
  initramfs?: string
  /** The packages the switch to dracut removes, as the device reports them. */
  initramfsRemoves: string[]
  /** The estimated background duration in seconds; null without a disk size. */
  estimate: number | null
}>()
const emit = defineEmits<{ confirm: [reason: string]; cancel: [] }>()

const { t, locale } = useI18n()
const id = useId()
const backup = ref(false)
const reason = ref('')
const typed = ref('')
const cancelButton = ref<ComponentPublicInstance | null>(null)
const card = ref<ComponentPublicInstance | null>(null)

const canConfirm = computed(() => backup.value && typed.value === props.hostname && reason.value.trim().length >= 2)

/** The information lines of the checklist, in the order of decision 24. */
const checks = computed(() => {
  const lines = [
    t('devices.disk.convert.check.restart'),
    t('devices.disk.convert.check.power'),
    t(props.tpmOnly ? 'devices.disk.convert.check.tpmOnly' : 'devices.disk.convert.check.pin'),
    props.estimate === null
      ? t('devices.disk.convert.check.durationUnknown')
      : t('devices.disk.convert.check.duration', { duration: formatDuration(props.estimate, locale.value) }),
  ]
  if (props.initramfs === 'initramfs-tools') {
    lines.push(props.initramfsRemoves.length > 0
      ? t('devices.disk.convert.check.initramfsSwitch', { packages: props.initramfsRemoves.join(', ') })
      : t('devices.disk.convert.check.initramfsSwitchUnknown'))
  }
  return lines
})

function focusCancel(): void {
  ;(cancelButton.value?.$el as HTMLElement | undefined)?.focus()
}

function focusCancelAfterEnter(): void {
  if ((card.value?.$el as HTMLElement | undefined)?.contains(document.activeElement)) return
  focusCancel()
}

// Every opening starts empty: a ticked acknowledgement or a typed hostname must never confirm a different request.
watch(
  () => [props.modelValue, props.hostname] as const,
  ([open]) => {
    backup.value = false
    reason.value = ''
    typed.value = ''
    if (open) void nextTick(focusCancel)
  },
  { immediate: true },
)

function onConfirm(): void {
  if (canConfirm.value) emit('confirm', reason.value.trim())
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="600"
    scrollable
    :transition="reducedMotion() ? false : 'dialog-transition'"
    :aria-labelledby="id + '-title'"
    :aria-describedby="id + '-explanation'"
    @update:model-value="(open: boolean) => !open && emit('cancel')"
    @after-enter="focusCancelAfterEnter"
  >
    <v-card
      ref="card"
      data-testid="encrypt-dialog"
      @keydown.esc.stop="emit('cancel')"
    >
      <v-card-title
        :id="id + '-title'"
        tag="h2"
        class="confirm-title"
      >
        {{ t('devices.disk.convert.title', { hostname }) }}
      </v-card-title>
      <v-card-text>
        <p :id="id + '-explanation'">
          {{ t('devices.disk.convert.explanation') }}
        </p>
        <v-checkbox
          v-model="backup"
          :label="t('devices.disk.convert.check.backup')"
          hide-details
          data-testid="encrypt-backup"
        />
        <ul
          class="pd-encrypt-checks"
          data-testid="encrypt-checks"
        >
          <li
            v-for="(line, i) in checks"
            :key="i"
          >
            {{ line }}
          </li>
        </ul>
        <v-textarea
          v-model="reason"
          :label="t('devices.revocation.reason')"
          :hint="t('devices.revocation.reasonHint')"
          persistent-hint
          :counter="500"
          :maxlength="500"
          rows="2"
          auto-grow
          autocomplete="off"
          data-testid="encrypt-reason"
          @keydown.enter.stop
        />
        <v-text-field
          v-model="typed"
          class="confirm-typed"
          :label="t('confirm.typeToConfirm', { text: hostname })"
          :hint="t('devices.disk.convert.typed')"
          persistent-hint
          autocomplete="off"
          spellcheck="false"
          data-testid="encrypt-typed"
          @keydown.enter.prevent
        />
        <div class="form-actions">
          <v-btn
            ref="cancelButton"
            variant="tonal"
            data-testid="encrypt-cancel"
            @click="emit('cancel')"
          >
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="error"
            variant="flat"
            :disabled="!canConfirm"
            data-testid="encrypt-accept"
            @click="onConfirm"
          >
            {{ t('devices.disk.convert.confirmLabel') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

