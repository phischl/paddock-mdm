<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useConfirm } from '../composables/useConfirm'
import { usePending } from '../composables/usePending'
import {
  availableToolCount,
  filterTools,
  getMcpTools,
  getPlatformMcpSettings,
  groupByTag,
  platformTools,
  savePlatformMcpSettings,
  toInput,
  validSelection,
  type McpSettings,
  type McpSettingsInput,
  type McpTool,
} from '../lib/platformMcp'
import { useProblemText } from '../lib/problems'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'

/**
 * The MCP policy of the platform (plan M14 §3.6 item 31, ADR 0044 decision 10): what platform administrators' MCP
 * sessions may do. Platform administrators connect with paddockctl mcp login and their own account; there are no
 * MCP tokens. Saving needs a step-up.
 */
const stepUpAction = 'mcp-settings'
const stepUpTarget = 'platform'

const { t } = useI18n()
const { pending, run } = usePending()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const settings = ref<McpSettings | null>(null)
const form = ref<McpSettingsInput>({ enabled: false, write_enabled: false, mode: 'all', allowed_operations: [] })
const tools = ref<McpTool[]>([])
const filter = ref('')
const problem = ref('')
const saved = ref(false)

const scope = computed(() => t('mcp.scope.platform'))
const neverSaved = computed(() => settings.value !== null && settings.value.updated_at === null)
const groups = computed(() => groupByTag(filterTools(tools.value, filter.value)))
const selectionValid = computed(() => validSelection(form.value))

function apply(s: McpSettings): void {
  settings.value = s
  form.value = toInput(s)
}

async function load(): Promise<void> {
  const [s, catalog] = await Promise.all([getPlatformMcpSettings(), getMcpTools()])
  if (typeof s === 'string') {
    problem.value = s
    return
  }
  apply(s)
  if (typeof catalog === 'string') problem.value = catalog
  else tools.value = platformTools(catalog)
}

async function save(input: McpSettingsInput): Promise<void> {
  problem.value = ''
  const res = await savePlatformMcpSettings(input)
  if (res === stepUpRequired) {
    startStepUp(stepUpAction, stepUpTarget, input)
    return
  }
  if (typeof res === 'string') {
    problem.value = res
    return
  }
  apply(res)
  saved.value = true
}

async function onSave(): Promise<void> {
  if (!selectionValid.value) return
  const input: McpSettingsInput = {
    ...form.value,
    allowed_operations: form.value.mode === 'all' ? [] : [...form.value.allowed_operations],
  }
  const confirmed = await confirm({
    title: t('mcp.confirm.title'),
    message: t('mcp.confirm.message', {
      count: availableToolCount(input, tools.value),
      scope: scope.value,
      writes: input.enabled && input.write_enabled ? 'allowed' : 'refused',
    }),
    confirmLabel: t('mcp.save'),
  })
  if (confirmed) await save(input)
}

onMounted(async () => {
  await load()
  const resumed = resumeStepUp<McpSettingsInput>(stepUpAction, stepUpTarget)
  if (!resumed) return
  await router.replace(withoutStepUpParam())
  if (resumed.failed) problem.value = 'step_up_failed'
  else await save(resumed.payload)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('mcp.title') }}</h1>
    <p class="summary">
      {{ t('mcp.intro', { scope }) }}
    </p>
    <v-alert
      type="info"
      variant="tonal"
      class="mcp-alert"
      data-testid="mcp-connect-hint"
    >
      {{ t('mcp.connectHint') }}
    </v-alert>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
      data-testid="mcp-problem"
    >
      {{ problemText(problem) }}
    </p>
    <form
      v-if="settings"
      class="form"
      novalidate
      @submit.prevent="run(onSave)"
    >
      <v-alert
        v-if="neverSaved"
        type="info"
        variant="tonal"
        class="mcp-alert"
        data-testid="mcp-defaults-hint"
      >
        {{ t('mcp.defaultsHint', { scope }) }}
      </v-alert>
      <v-alert
        v-else-if="!settings.enabled"
        type="warning"
        variant="tonal"
        class="mcp-alert"
        data-testid="mcp-disabled-hint"
      >
        {{ t('mcp.disabledHint', { scope }) }}
      </v-alert>
      <v-switch
        id="mcp-enabled"
        v-model="form.enabled"
        :label="t('mcp.enabled')"
        color="primary"
        inset
        hide-details
        data-testid="mcp-enabled"
      />
      <v-switch
        id="mcp-write-enabled"
        v-model="form.write_enabled"
        :label="t('mcp.writeEnabled')"
        color="primary"
        inset
        hide-details
        data-testid="mcp-write-enabled"
      />
      <v-radio-group
        v-model="form.mode"
        hide-details
        data-testid="mcp-mode"
      >
        <v-radio
          value="all"
          :label="t('mcp.mode.all')"
          data-testid="mcp-mode-all"
        />
        <v-radio
          value="selected"
          :label="t('mcp.mode.selected')"
          data-testid="mcp-mode-selected"
        />
      </v-radio-group>
      <fieldset
        v-if="form.mode === 'selected'"
        class="mcp-tools"
        data-testid="mcp-tools"
      >
        <legend class="pd-type-section">
          {{ t('mcp.tools') }}
        </legend>
        <v-text-field
          id="mcp-filter"
          v-model="filter"
          :label="t('mcp.filter')"
          clearable
          hide-details
          data-testid="mcp-filter"
        />
        <p
          v-if="!selectionValid"
          class="form-error"
          role="alert"
          data-testid="mcp-select-hint"
        >
          {{ t('mcp.selectHint') }}
        </p>
        <section
          v-for="group in groups"
          :key="group.tag"
          class="mcp-group"
          :data-testid="'mcp-group-' + group.tag"
        >
          <h2 class="pd-type-section">
            {{ group.tag }}
          </h2>
          <div
            v-for="tool in group.tools"
            :key="tool.operation_id"
            class="mcp-tool"
            :data-testid="'mcp-tool-' + tool.operation_id"
          >
            <v-checkbox
              v-model="form.allowed_operations"
              :value="tool.operation_id"
              :label="tool.summary"
              :disabled="tool.step_up"
              hide-details
              density="compact"
            />
            <code class="mcp-operation">{{ tool.operation_id }}</code>
            <v-chip
              size="small"
              variant="tonal"
              :color="tool.class === 'write' ? 'warning' : undefined"
            >
              {{ t('mcp.class.' + tool.class) }}
            </v-chip>
            <span
              v-if="tool.step_up"
              class="mcp-portal-only"
            >{{ t('mcp.portalOnly') }}</span>
          </div>
        </section>
      </fieldset>
      <div class="form-actions">
        <v-btn
          type="submit"
          :loading="pending"
          :disabled="pending || !selectionValid"
          color="primary"
          data-testid="save-mcp"
        >
          {{ t('mcp.save') }}
        </v-btn>
      </div>
    </form>
    <v-snackbar
      v-model="saved"
      color="success"
      data-testid="mcp-saved"
    >
      {{ t('mcp.saved') }}
    </v-snackbar>
  </section>
</template>

<style scoped>
.mcp-alert {
  margin-bottom: var(--pd-space-4);
}

.mcp-tools {
  border: 0;
  display: grid;
  gap: var(--pd-space-3);
  margin: 0;
  padding: 0;
}

.mcp-group h2 {
  margin-bottom: var(--pd-space-1);
}

.mcp-tool {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--pd-space-2);
}

.mcp-operation {
  font-family: var(--pd-font-mono);
  overflow-wrap: anywhere;
}

.mcp-portal-only {
  color: var(--pd-text-muted);
}
</style>
