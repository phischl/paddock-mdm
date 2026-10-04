import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useConfirm } from '../composables/useConfirm'
import { allGroups } from './devices'

/**
 * Dialog state of the managed files and units pages: one dialog for create (target null) and edit, delete after a
 * modal confirmation. save and remove return null or a problem code; reload refreshes the list.
 */
export function useManagedPage<T extends { id: string }, I>(opts: {
  save: (id: string | null, input: I) => Promise<string | null>
  remove: (id: string) => Promise<string | null>
  label: (item: T) => string
  messages: { deleteTitle: string; deleteConfirm: string }
  reload: () => void
}) {
  const { t } = useI18n()
  const confirm = useConfirm()
  const groups = ref<{ id: string; name: string }[]>([])
  const open = ref(false)
  const target = ref<T | null>(null)
  const problem = ref('')
  const pageProblem = ref('')
  onMounted(async () => {
    groups.value = await allGroups()
  })

  function openDialog(item: T | null): void {
    target.value = item
    problem.value = ''
    open.value = true
  }

  async function submit(input: I): Promise<void> {
    problem.value = (await opts.save(target.value?.id ?? null, input)) ?? ''
    if (problem.value) return
    open.value = false
    opts.reload()
  }

  async function remove(item: T): Promise<void> {
    pageProblem.value = ''
    const confirmed = await confirm({
      title: t(opts.messages.deleteTitle),
      message: t(opts.messages.deleteConfirm, { name: opts.label(item) }),
      confirmLabel: t('common.delete'),
      destructive: true,
    })
    if (!confirmed) return
    pageProblem.value = (await opts.remove(item.id)) ?? ''
    opts.reload()
  }

  function groupName(id: string | null | undefined): string {
    if (!id) return t('managed.allDevices')
    return groups.value.find((g) => g.id === id)?.name ?? id
  }

  return { groups, open, target, problem, pageProblem, openDialog, submit, remove, groupName }
}
