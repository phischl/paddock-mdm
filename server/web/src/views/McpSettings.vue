<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import McpToolPicker from '../components/McpToolPicker.vue'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import { formatDateTime } from '../lib/format'
import {
  allowedCount, getMcpCatalog, getMcpSettings, mcpGuide, policyForm, policyInput, saveMcpSettings, scopeTools,
  type McpPolicyForm, type McpProblem, type McpSettings, type McpSettingsInput, type McpTool,
} from '../lib/mcp'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'

/**
 * The organization's MCP policy (plan M14 §3.6 item 29, ADR 0044 decision 10): whether MCP sessions get in, whether
 * they may change data, and which tools they may call. Saving needs an organization administrator with a step-up.
 */
const { t, locale } = useI18n()
const { pending, run } = usePending()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()

const settings = ref<McpSettings | null>(null)
const tools = ref<McpTool[]>([])
const form = reactive<McpPolicyForm>({ enabled: false, writeEnabled: false, mode: 'all', selected: [] })
const problem = ref<McpProblem | null>(null)
const selectionMissing = ref(false)
const saved = ref(false)

const scope = computed(() => t('mcp.scope.organization'))
const readOnly = computed(() => !session.canDelete)
const neverSaved = computed(() => settings.value !== null && settings.value.updated_at === null)

// A policy that was never saved starts with changes allowed once the MCP is switched on (ticket PDK-440); the
// administrator may still switch them off before saving. Synchronous, so a payload applied with enabled before
// write_enabled (a resumed step-up) keeps its own write choice.
watch(() => form.enabled, (on, was) => {
  if (on && !was && neverSaved.value) form.writeEnabled = true
}, { flush: 'sync' })

function apply(s: McpSettings): void {
  settings.value = s
  Object.assign(form, policyForm(s))
}

async function submit(input: McpSettingsInput): Promise<void> {
  problem.value = null
  const res = await saveMcpSettings(input)
  if ('code' in res) {
    if (res.code === stepUpRequired) {
      startStepUp('mcp-settings', 'organization', input)
      return
    }
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}

async function onSave(): Promise<void> {
  problem.value = null
  const input = policyInput(form, tools.value)
  selectionMissing.value = input.mode === 'selected' && input.allowed_operations.length === 0
  if (selectionMissing.value) return
  const confirmed = await confirm({
    title: t('mcp.confirm.title'),
    message: t('mcp.confirm.message', {
      count: allowedCount(input, tools.value), scope: scope.value, writes: input.write_enabled ? 'allowed' : 'refused',
    }),
    confirmLabel: t('mcp.save'),
  })
  if (confirmed) await submit(input)
}

onMounted(async () => {
  const [s, catalog] = await Promise.all([getMcpSettings(), getMcpCatalog()])
  if (typeof catalog === 'string') problem.value = { code: catalog }
  else tools.value = scopeTools(catalog, 'organization')
  if (typeof s === 'string') {
    problem.value = { code: s }
    return
  }
  apply(s)
  const resumed = resumeStepUp<McpSettingsInput>('mcp-settings', 'organization')
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) {
    problem.value = { code: 'step_up_failed' }
    return
  }
  Object.assign(form, {
    enabled: resumed.payload.enabled, writeEnabled: resumed.payload.write_enabled, mode: resumed.payload.mode,
    selected: [...resumed.payload.allowed_operations],
  })
  await submit(resumed.payload)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('mcp.title') }}</h1>
    <p
      v-if="settings?.updated_at"
      class="summary"
      data-testid="mcp-updated-at"
    >
      {{ t('loginSettings.updatedAt', { at: formatDateTime(settings.updated_at, locale) }) }}
    </p>
    <p class="summary">
      {{ t('mcp.intro', { scope }) }}
    </p>
    <v-alert
      v-if="neverSaved"
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="mcp-defaults-hint"
    >
      {{ t('mcp.defaultsHint', { scope }) }}
    </v-alert>
    <v-alert
      v-else-if="settings && !settings.enabled"
      type="warning"
      variant="tonal"
      class="conflict"
      data-testid="mcp-disabled-hint"
    >
      {{ t('mcp.disabledHint', { scope }) }}
    </v-alert>
    <v-alert
      type="info"
      variant="tonal"
      class="conflict"
      data-testid="mcp-connect-hint"
    >
      {{ t('mcp.connectHint') }}
      <a
        :href="mcpGuide"
        target="_blank"
        rel="noopener noreferrer"
        data-testid="mcp-guide"
      >{{ t('mcp.guide') }}</a>
    </v-alert>
    <form
      v-if="settings"
      class="form settings-form"
      novalidate
      @submit.prevent="run(onSave)"
    >
      <fieldset :disabled="readOnly">
        <legend>{{ t('mcp.legend') }}</legend>
        <v-switch
          id="mcp-enabled"
          v-model="form.enabled"
          :label="t('mcp.enabled')"
          :disabled="readOnly"
          color="primary"
          inset
          data-testid="mcp-enabled"
        />
        <v-switch
          id="mcp-write-enabled"
          v-model="form.writeEnabled"
          :label="t('mcp.writeEnabled')"
          :disabled="readOnly"
          color="primary"
          inset
          data-testid="mcp-write-enabled"
        />
        <v-radio-group
          v-model="form.mode"
          :disabled="readOnly"
          hide-details
          data-testid="mcp-mode"
        >
          <v-radio
            :label="t('mcp.mode.all')"
            value="all"
            data-testid="mcp-mode-all"
          />
          <v-radio
            :label="t('mcp.mode.selected')"
            value="selected"
            data-testid="mcp-mode-selected"
          />
        </v-radio-group>
        <McpToolPicker
          v-if="form.mode === 'selected'"
          v-model="form.selected"
          :tools="tools"
          :disabled="readOnly"
        />
        <p
          v-if="selectionMissing"
          class="form-error"
          role="alert"
        >
          {{ t('mcp.selectAtLeastOne') }}
        </p>
      </fieldset>
      <p
        v-if="problem"
        class="form-error"
        role="alert"
        data-testid="mcp-problem"
      >
        {{ problemText(problem.code) }}<template v-if="problem.detail">
          ({{ problem.detail }})
        </template>
      </p>
      <div
        v-if="!readOnly"
        class="form-actions"
      >
        <v-btn
          type="submit"
          :loading="pending"
          :disabled="pending"
          color="primary"
          data-testid="save-mcp"
        >
          {{ t('mcp.save') }}
        </v-btn>
      </div>
    </form>
    <p
      v-else-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem.code) }}
    </p>
    <v-snackbar
      v-model="saved"
      color="success"
      data-testid="mcp-saved"
    >
      {{ t('mcp.saved') }}
    </v-snackbar>
  </section>
</template>
