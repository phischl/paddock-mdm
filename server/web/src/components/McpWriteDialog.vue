<script setup lang="ts">
import { computed, nextTick, onMounted, ref, useId, watch, type ComponentPublicInstance } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import { formatDateTime } from '../lib/format'
import { reducedMotion } from '../lib/pageContext'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The administrator's own MCP write access (ADR 0044 decision 5, the third layer; plan M14 §3.6 item 32): enabling is
 * confirmed and needs a step-up, disabling is confirmed and takes effect at once.
 */
const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [open: boolean] }>()

const stepUpAction = 'mcp-write'
const stepUpTarget = 'me'

const { t, locale } = useI18n()
const id = useId()
const session = useSessionStore()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const { pending, run } = usePending()
const problem = ref('')
const closeButton = ref<ComponentPublicInstance | null>(null)

const scope = computed(() => t('mcp.write.scope.' + (session.isPlatform ? 'platform' : 'organization')))
const state = computed(() => {
  if (!session.mcpWriteEnabled) return t('mcp.write.state.off')
  const since = session.me?.mcp_write_enabled_at
  return since ? t('mcp.write.state.on', { time: formatDateTime(since, locale.value) }) : t('mcp.write.state.onUnknown')
})

function close(): void {
  emit('update:modelValue', false)
}

watch(
  () => props.modelValue,
  (open) => {
    if (open) problem.value = ''
  },
)

async function apply(enabled: boolean, stepUp: boolean): Promise<void> {
  problem.value = ''
  const res = await session.setMcpWrite(enabled)
  if (res === stepUpRequired && enabled && stepUp) {
    startStepUp(stepUpAction, stepUpTarget)
    return
  }
  problem.value = res ?? ''
}

function onEnable(): Promise<void | undefined> {
  return run(async () => {
    const confirmed = await confirm({
      title: t('mcp.write.confirmEnable.title'),
      message: t('mcp.write.confirmEnable.message'),
      confirmLabel: t('mcp.write.enable'),
      destructive: true,
    })
    if (confirmed) await apply(true, true)
  })
}

function onDisable(): Promise<void | undefined> {
  return run(async () => {
    const confirmed = await confirm({
      title: t('mcp.write.confirmDisable.title'),
      message: t('mcp.write.confirmDisable.message'),
      confirmLabel: t('mcp.write.disable'),
    })
    if (confirmed) await apply(false, false)
  })
}

// The step-up is a full navigation that comes back to the page the dialog was opened on; the dialog reopens there and
// repeats the enable call once, or shows why the step-up was refused.
onMounted(async () => {
  const resumed = resumeStepUp<null>(stepUpAction, stepUpTarget)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  emit('update:modelValue', true)
  await nextTick()
  if (resumed.failed) {
    problem.value = 'step_up_failed'
    return
  }
  await run(() => apply(true, false))
})

function focusClose(): void {
  ;(closeButton.value?.$el as HTMLElement | undefined)?.focus()
}
</script>

<template>
  <v-dialog
    :model-value="modelValue"
    max-width="560"
    :transition="reducedMotion() ? false : 'dialog-transition'"
    :aria-labelledby="id + '-title'"
    :aria-describedby="id + '-state'"
    @update:model-value="(open: boolean) => !open && close()"
    @after-enter="focusClose"
  >
    <v-card data-testid="mcp-write-dialog">
      <v-card-title
        :id="id + '-title'"
        tag="h2"
        class="mcp-write-title"
      >
        {{ t('mcp.write.title') }}
      </v-card-title>
      <v-card-text>
        <p>{{ t('mcp.write.explain', { scope }) }}</p>
        <p class="mcp-write-connect">
          {{ t('mcp.write.connect') }}
        </p>
        <p
          :id="id + '-state'"
          class="mcp-write-state"
          role="status"
          data-testid="mcp-write-state"
        >
          {{ state }}
        </p>
        <v-alert
          v-if="problem"
          type="error"
          variant="tonal"
          density="compact"
          class="mcp-write-problem"
          data-testid="mcp-write-problem"
        >
          {{ problemText(problem) }}
        </v-alert>
        <div class="form-actions">
          <v-btn
            ref="closeButton"
            variant="tonal"
            data-testid="mcp-write-close"
            @click="close"
          >
            {{ t('mcp.write.close') }}
          </v-btn>
          <v-btn
            v-if="session.mcpWriteEnabled"
            variant="flat"
            color="primary"
            :loading="pending"
            data-testid="mcp-write-disable"
            @click="onDisable"
          >
            {{ t('mcp.write.disable') }}
          </v-btn>
          <v-btn
            v-else
            variant="flat"
            color="error"
            :loading="pending"
            data-testid="mcp-write-enable"
            @click="onEnable"
          >
            {{ t('mcp.write.enable') }}
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.mcp-write-title {
  white-space: normal;
}

.mcp-write-connect {
  margin-top: var(--pd-space-3);
}

.mcp-write-state {
  margin-top: var(--pd-space-3);
  font-weight: 600;
}

.mcp-write-problem {
  margin-top: var(--pd-space-3);
}
</style>
