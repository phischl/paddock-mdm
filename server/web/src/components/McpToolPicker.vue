<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { filterTools, groupByTag, selectable, type McpTool } from '../lib/mcp'
import { mcpClassStatus } from '../lib/status'
import StatusChip from './StatusChip.vue'

/**
 * The tools of an MCP policy (plan M14 §3.6 item 29): grouped by tag, narrowed by a client-side filter over operation
 * id and summary; step-up tools are listed but never selectable (ADR 0044 decision 5).
 */
const props = defineProps<{ tools: McpTool[]; disabled?: boolean }>()
const selected = defineModel<string[]>({ required: true })
const { t } = useI18n()
const query = ref('')

const groups = computed(() => groupByTag(filterTools(props.tools, query.value)))

function toggle(id: string, on: boolean | null): void {
  selected.value = on ? [...new Set([...selected.value, id])] : selected.value.filter((s) => s !== id)
}
</script>

<template>
  <div
    class="mcp-picker"
    data-testid="mcp-tool-picker"
  >
    <v-text-field
      id="mcp-tool-filter"
      v-model="query"
      :label="t('mcp.filter')"
      clearable
      hide-details
      data-testid="mcp-tool-filter"
    />
    <section
      v-for="group in groups"
      :key="group.tag"
      class="mcp-group"
      :data-tag="group.tag"
    >
      <h3 class="mcp-group-title">
        {{ group.tag }}
      </h3>
      <ul class="mcp-tools">
        <li
          v-for="tool in group.tools"
          :key="tool.operation_id"
          class="mcp-tool"
          :data-tool="tool.operation_id"
        >
          <v-checkbox
            :id="'mcp-tool-' + tool.operation_id"
            :model-value="selected.includes(tool.operation_id)"
            :disabled="disabled || !selectable(tool)"
            :aria-describedby="'mcp-tool-' + tool.operation_id + '-summary'"
            density="compact"
            hide-details
            @update:model-value="toggle(tool.operation_id, $event)"
          >
            <template #label>
              <span class="mono">{{ tool.operation_id }}</span>
            </template>
          </v-checkbox>
          <StatusChip
            :status="mcpClassStatus(tool.class).status"
            :label="t(mcpClassStatus(tool.class).label)"
          />
          <!-- Outside the checkbox: text inside a disabled control inherits its opacity and fails the contrast. -->
          <span
            :id="'mcp-tool-' + tool.operation_id + '-summary'"
            class="mcp-tool-summary"
          >{{ tool.summary }}</span>
          <span
            v-if="tool.step_up"
            class="mcp-tool-portal"
            data-testid="mcp-tool-portal-only"
          >{{ t('mcp.portalOnly') }}</span>
        </li>
      </ul>
    </section>
  </div>
</template>

<style scoped>
.mcp-picker { display: flex; flex-direction: column; gap: 0.75rem; }
.mcp-group-title { font-size: 13px; font-weight: 600; margin: 0; }
.mcp-tools { list-style: none; margin: 0; padding: 0; }
.mcp-tool { display: flex; flex-wrap: wrap; align-items: center; gap: 0 0.5rem; }
.mcp-tool :deep(.v-checkbox) { flex: 0 0 auto; width: auto; max-width: none; }
.mcp-tool-summary { color: var(--pd-text-secondary); }
.mcp-tool-portal { color: var(--pd-text-muted); font-style: italic; }
</style>
