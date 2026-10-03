import { computed, ref } from 'vue'
import { useDeviceGroups } from './deviceGroups'

export interface DeviceGroupInput {
  name: string
  description: string
}

/** Dialog state and handlers of the device group page. */
export function useDeviceGroupPage() {
  const groups = useDeviceGroups()
  const createOpen = ref(false)
  const createProblem = ref('')
  const editing = ref<string | null>(null)
  const editProblem = ref('')
  const deleting = ref<string | null>(null)
  const deleteProblem = ref('')

  const editTarget = computed(() => groups.items.value.find((g) => g.id === editing.value) ?? null)
  const deleteTarget = computed(() => groups.items.value.find((g) => g.id === deleting.value) ?? null)

  function openCreate(): void {
    createProblem.value = ''
    createOpen.value = true
  }

  async function onCreate(form: DeviceGroupInput): Promise<void> {
    createProblem.value = (await groups.create(form.name, form.description)) ?? ''
    if (!createProblem.value) createOpen.value = false
  }

  function openEdit(id: string): void {
    editProblem.value = ''
    editing.value = id
  }

  function closeEdit(): void {
    editing.value = null
  }

  async function onEdit(form: DeviceGroupInput): Promise<void> {
    if (!editTarget.value) return
    editProblem.value = (await groups.update(editTarget.value.id, form.name, form.description)) ?? ''
    if (!editProblem.value) editing.value = null
  }

  function openDelete(id: string): void {
    deleteProblem.value = ''
    deleting.value = id
  }

  function closeDelete(): void {
    deleting.value = null
  }

  async function onDelete(): Promise<void> {
    if (!deleteTarget.value) return
    deleteProblem.value = (await groups.remove(deleteTarget.value.id)) ?? ''
    if (!deleteProblem.value) deleting.value = null
  }

  return {
    groups, createOpen, createProblem, editTarget, editProblem, deleteTarget, deleteProblem,
    openCreate, onCreate, openEdit, closeEdit, onEdit, openDelete, closeDelete, onDelete,
  }
}
