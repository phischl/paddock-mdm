import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useRolloutsEnabled, type UrgentInput } from './configRollouts'
import { allGroups } from './devices'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from './stepUp'

/**
 * Dialog state of the pages of group-scoped definitions (managed files and units, package holds): one dialog for
 * create (target null) and edit, delete after a modal confirmation. save and remove return null or a problem code;
 * reload refreshes the list. Both carry the urgent opt-out of a rollout (plan M11 decision 37); a write the server
 * refuses with step_up_required is repeated once after the step-up when stepUpAction is set.
 */
export function useManagedPage<T extends { id: string }, I>(opts: {
  save: (id: string | null, input: I) => Promise<string | null>
  remove: (id: string, urgent?: UrgentInput) => Promise<string | null>
  label: (item: T) => string
  messages: { deleteTitle: string; deleteConfirm: string }
  reload: () => void
  stepUpAction?: string
}) {
  const { t } = useI18n()
  const router = useRouter()
  const rolloutsEnabled = useRolloutsEnabled()
  const deleting = ref<T | null>(null)
  const deletePending = ref(false)
  const groups = ref<{ id: string; name: string }[]>([])
  const open = ref(false)
  const target = ref<T | null>(null)
  const problem = ref('')
  const pageProblem = ref('')
  /** A pending create or edit: the step-up returns to the list, so the edited item's ID travels with the input. */
  interface Pending { id: string | null; input: I }
  interface PendingDelete { id: string; urgent: UrgentInput }
  onMounted(async () => {
    groups.value = await allGroups()
    if (!opts.stepUpAction) return
    const resumed = resumeStepUp<Pending>(opts.stepUpAction, 'list')
    const resumedDelete = resumeStepUp<PendingDelete>(opts.stepUpAction + '-delete', 'list')
    if (!resumed && !resumedDelete) return
    await router.replace(withoutStepUpParam())
    if (resumed) {
      pageProblem.value = resumed.failed ? 'step_up_failed' : ((await opts.save(resumed.payload.id, resumed.payload.input)) ?? '')
    } else if (resumedDelete) {
      pageProblem.value = resumedDelete.failed ? 'step_up_failed' : ((await opts.remove(resumedDelete.payload.id, resumedDelete.payload.urgent)) ?? '')
    }
    opts.reload()
  })

  function openDialog(item: T | null): void {
    target.value = item
    problem.value = ''
    open.value = true
  }

  async function submit(input: I): Promise<void> {
    const id = target.value?.id ?? null
    problem.value = (await opts.save(id, input)) ?? ''
    if (problem.value === stepUpRequired && opts.stepUpAction) startStepUp(opts.stepUpAction, 'list', { id, input } satisfies Pending)
    if (problem.value) return
    open.value = false
    opts.reload()
  }

  // Async so the pages' run() wrappers keep their signature; the request itself runs on confirmDelete.
  async function remove(item: T): Promise<void> {
    pageProblem.value = ''
    deleting.value = item
  }

  const deleteMessage = computed(() => (deleting.value ? t(opts.messages.deleteConfirm, { name: opts.label(deleting.value) }) : ''))

  async function confirmDelete(urgent: UrgentInput): Promise<void> {
    const item = deleting.value
    if (!item) return
    deleting.value = null
    deletePending.value = true
    try {
      pageProblem.value = (await opts.remove(item.id, urgent)) ?? ''
    } finally {
      deletePending.value = false
    }
    if (pageProblem.value === stepUpRequired && opts.stepUpAction) {
      startStepUp(opts.stepUpAction + '-delete', 'list', { id: item.id, urgent } satisfies PendingDelete)
    }
    opts.reload()
  }

  function groupName(id: string | null | undefined): string {
    if (!id) return t('managed.allDevices')
    return groups.value.find((g) => g.id === id)?.name ?? id
  }

  return {
    groups, open, target, problem, pageProblem, openDialog, submit, remove, groupName, rolloutsEnabled, deleting, deletePending, deleteMessage,
    confirmDelete,
  }
}
