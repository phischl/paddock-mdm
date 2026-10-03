import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceGroup } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { createDeviceGroup, deleteDeviceGroup, updateDeviceGroup } from './deviceGroups'

export interface DeviceGroupInput {
  name: string
  description: string
}

/** Dialog state and handlers of the device group page; reload refreshes the list after a change. */
export function useDeviceGroupPage(reload: () => void) {
  const { t } = useI18n()
  const confirm = useConfirm()
  const createOpen = ref(false)
  const createProblem = ref('')
  const editTarget = ref<DeviceGroup | null>(null)
  const editProblem = ref('')
  const pageProblem = ref('')

  function openCreate(): void {
    createProblem.value = ''
    createOpen.value = true
  }

  async function onCreate(form: DeviceGroupInput): Promise<void> {
    createProblem.value = (await createDeviceGroup(form.name, form.description)) ?? ''
    if (createProblem.value) return
    createOpen.value = false
    reload()
  }

  function openEdit(group: DeviceGroup): void {
    editProblem.value = ''
    editTarget.value = group
  }

  function closeEdit(): void {
    editTarget.value = null
  }

  async function onEdit(form: DeviceGroupInput): Promise<void> {
    if (!editTarget.value) return
    editProblem.value = (await updateDeviceGroup(editTarget.value.id, form.name, form.description)) ?? ''
    if (editProblem.value) return
    editTarget.value = null
    reload()
  }

  /** Deletes after confirmation in the modal; a failure is shown on the page. */
  async function onDelete(group: DeviceGroup): Promise<void> {
    pageProblem.value = ''
    const confirmed = await confirm({
      title: t('deviceGroups.deleteTitle'),
      message: t('deviceGroups.deleteConfirm', { name: group.name }),
      confirmLabel: t('common.delete'),
      destructive: true,
    })
    if (!confirmed) return
    pageProblem.value = (await deleteDeviceGroup(group.id)) ?? ''
    reload()
  }

  return {
    createOpen, createProblem, editTarget, editProblem, pageProblem,
    openCreate, onCreate, openEdit, closeEdit, onEdit, onDelete,
  }
}
