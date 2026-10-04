import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { AgentReleaseDetail } from '../api/client'
import { useConfirm, type ConfirmOptions } from '../composables/useConfirm'
import { getAgentRelease, rolloutActionsFor, runRolloutAction, type RolloutAction } from './agentReleases'

/** State and handlers of the agent release detail page. */
export function useAgentReleasePage(version: () => string) {
  const { t } = useI18n()
  const confirm = useConfirm()
  const detail = ref<AgentReleaseDetail | null>(null)
  const problem = ref('')

  async function load(): Promise<void> {
    const d = await getAgentRelease(version())
    if (typeof d === 'string') {
      problem.value = d
      return
    }
    detail.value = d
  }

  const actions = computed<RolloutAction[]>(() => (detail.value ? rolloutActionsFor(detail.value) : []))

  /** Starting a rollout reaches every device eventually: the version has to be typed. */
  function confirmation(action: RolloutAction, v: string): ConfirmOptions {
    const base = {
      title: t('agentReleases.actions.' + action + '.title'),
      message: t('agentReleases.actions.' + action + '.confirm', { version: v }),
      confirmLabel: t('agentReleases.actions.' + action + '.label'),
    }
    return action === 'start' ? { ...base, destructive: true, requireTypedText: v } : base
  }

  async function run(action: RolloutAction): Promise<void> {
    if (!detail.value) return
    const v = detail.value.release.version
    problem.value = ''
    if (!(await confirm(confirmation(action, v)))) return
    problem.value = (await runRolloutAction(v, action)) ?? ''
    await load()
  }

  return { detail, problem, actions, load, run }
}
