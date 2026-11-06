<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import TimeCell from './TimeCell.vue'
import {
  backupKinds, emptyPlan, newestSuccess, planErrors, restoreComponents, restoreWord, timeLeft,
  type BackupOverview, type BackupRestorePlan, type PlanInput,
} from '../lib/backup'

/**
 * The restore plan dialog (plan M15 decisions 25 to 27): kind, source, point in time with the newest success of the
 * source as the bound, components and the typed word. Once the plan exists the same dialog shows its host_command
 * exactly as the API returned it, with Copy and the time left; the browser never builds that text.
 */
const props = defineProps<{
  overview: BackupOverview | null
  /** The plan to show; null while the form is asked for. */
  plan: BackupRestorePlan | null
  /** The message of the last refused request. */
  problem: string
  pending: boolean
}>()
const emit = defineEmits<{ submit: [input: PlanInput]; close: [] }>()

const { t } = useI18n()
const form = reactive<PlanInput>(emptyPlan())
const touched = ref(false)
const copied = ref(false)
const now = ref(new Date())
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { timer = setInterval(() => { now.value = new Date() }, 15_000) })
onBeforeUnmount(() => clearInterval(timer))

const sources = computed(() => [
  { value: null as string | null, title: t('backup.restore.sourceRepo') },
  ...(props.overview?.targets.filter((x) => x.enabled).map((x) => ({ value: x.id as string | null, title: x.name })) ?? []),
])
const bound = computed(() => (props.overview ? newestSuccess(props.overview, form.sourceTargetId) : null))
const errors = computed(() => (touched.value ? planErrors(form, now.value) : []))
const left = computed(() => (props.plan?.expires_at ? timeLeft(props.plan.expires_at, now.value) : null))
const title = computed(() => t(props.plan ? 'backup.restore.commandTitle' : 'backup.restore.planTitle'))

function toggle(component: (typeof restoreComponents)[number], on: boolean): void {
  form.components = on ? [...form.components, component] : form.components.filter((c) => c !== component)
}

function submit(): void {
  touched.value = true
  if (planErrors(form, now.value).length === 0) emit('submit', { ...form, components: [...form.components] })
}

async function copy(): Promise<void> {
  if (!props.plan) return
  await navigator.clipboard.writeText(props.plan.host_command)
  copied.value = true
}
</script>

<template>
  <v-dialog
    model-value
    max-width="44rem"
    persistent
    :aria-label="title"
    @keydown.esc.stop="emit('close')"
  >
    <v-card
      :title="title"
      data-testid="backup-restore-dialog"
    >
      <v-card-text>
        <template v-if="plan">
          <p>{{ t('backup.restore.commandIntro') }}</p>
          <pre
            class="mono"
            tabindex="0"
            :aria-label="t('backup.restore.commandLabel')"
            data-testid="backup-restore-command"
          >{{ plan.host_command }}</pre>
          <p
            v-if="plan.expires_at"
            class="pd-muted"
            data-testid="backup-restore-expiry"
          >
            <template v-if="left">
              {{ t('backup.restore.expiresIn', { hours: left.hours, minutes: left.minutes }) }}
            </template>
            <template v-else>
              {{ t('backup.restore.expired') }}
            </template>
            <TimeCell :iso="plan.expires_at" />
          </p>
          <div class="form-actions">
            <span
              v-if="copied"
              role="status"
            >{{ t('tokens.copied') }}</span>
            <v-btn
              variant="tonal"
              data-testid="backup-restore-copy"
              @click="copy"
            >
              {{ t('tokens.copy') }}
            </v-btn>
            <v-btn
              color="primary"
              data-testid="backup-restore-done"
              @click="emit('close')"
            >
              {{ t('backup.restore.done') }}
            </v-btn>
          </div>
        </template>
        <form
          v-else
          class="form"
          novalidate
          data-testid="backup-restore-form"
          @submit.prevent="submit"
        >
          <v-alert
            type="warning"
            variant="tonal"
            class="conflict"
            data-testid="backup-restore-consequence"
          >
            {{ t('backup.restore.consequence') }}
          </v-alert>
          <p
            v-if="problem"
            class="form-error"
            role="alert"
            data-testid="backup-restore-problem"
          >
            {{ problem }}
          </p>
          <v-radio-group
            v-model="form.kind"
            :label="t('backup.restore.kind')"
            inline
            data-testid="backup-restore-kind"
          >
            <v-radio
              :label="t('backup.restore.kinds.components')"
              value="components"
              data-testid="backup-restore-kind-components"
            />
            <v-radio
              :label="t('backup.restore.kinds.point_in_time')"
              value="point_in_time"
              data-testid="backup-restore-kind-point_in_time"
            />
          </v-radio-group>
          <v-select
            v-model="form.sourceTargetId"
            :items="sources"
            item-title="title"
            item-value="value"
            :label="t('backup.restore.source')"
            data-testid="backup-restore-source"
          />
          <ul
            v-if="bound"
            class="pd-muted"
            data-testid="backup-restore-bound"
          >
            <li
              v-for="kind in backupKinds"
              :key="kind"
            >
              {{ t('backup.kinds.' + kind) }}:
              <TimeCell
                v-if="bound[kind]"
                :iso="bound[kind]!"
              />
              <template v-else>
                {{ t('backup.restore.noSuccess') }}
              </template>
            </li>
          </ul>
          <v-text-field
            v-if="form.kind === 'point_in_time'"
            id="backup-restore-at"
            v-model="form.at"
            type="datetime-local"
            :label="t('backup.restore.at')"
            :hint="t('backup.restore.atHint')"
            persistent-hint
            :error-messages="errors.includes('at') ? [t('backup.restore.atInvalid')] : []"
          />
          <fieldset
            class="form"
            data-testid="backup-restore-components"
          >
            <legend class="pd-type-caption">
              {{ t('backup.restore.components') }}
            </legend>
            <v-checkbox
              v-for="component in restoreComponents"
              :key="component"
              :model-value="form.components.includes(component)"
              :label="t('backup.restore.componentNames.' + component)"
              density="compact"
              hide-details
              :data-testid="'backup-restore-component-' + component"
              @update:model-value="(v: boolean | null) => toggle(component, v === true)"
            />
            <p
              v-if="errors.includes('components')"
              class="form-error"
              role="alert"
            >
              {{ t('backup.restore.componentsInvalid') }}
            </p>
          </fieldset>
          <v-text-field
            id="backup-restore-word"
            v-model="form.confirmation"
            :label="t('backup.restore.typeWord', { word: restoreWord })"
            autocomplete="off"
            :error-messages="errors.includes('confirmation') ? [t('backup.restore.wordInvalid', { word: restoreWord })] : []"
            data-testid="backup-restore-word"
          />
          <div class="form-actions">
            <v-btn
              variant="text"
              data-testid="backup-restore-cancel"
              @click="emit('close')"
            >
              {{ t('common.cancel') }}
            </v-btn>
            <v-btn
              type="submit"
              color="error"
              :loading="pending"
              :disabled="pending || form.confirmation !== restoreWord"
              data-testid="backup-restore-submit"
            >
              {{ t('backup.restore.approve') }}
            </v-btn>
          </div>
        </form>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>
