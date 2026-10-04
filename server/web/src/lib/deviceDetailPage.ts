import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceDetail, EffectiveConfig } from '../api/client'
import { useConfirm, type ConfirmOptions } from '../composables/useConfirm'
import { actionsFor, allGroups, getDevice, getEffectiveConfig, runDeviceAction, setDeviceGroups, type DeviceAction } from './devices'
import { useSessionStore } from '../stores/session'

/** State and handlers of the device detail page. */
export function useDeviceDetailPage(id: () => string) {
  const { t } = useI18n()
  const confirm = useConfirm()
  const session = useSessionStore()
  const device = ref<DeviceDetail | null>(null)
  const config = ref<EffectiveConfig | null>(null)
  const groups = ref<{ id: string; name: string }[]>([])
  const selectedGroups = ref<string[]>([])
  const problem = ref('')
  const saved = ref(false)

  async function load(): Promise<void> {
    const [d, c, g] = await Promise.all([getDevice(id()), getEffectiveConfig(id()), allGroups()])
    if (typeof d === 'string') {
      problem.value = d
      return
    }
    device.value = d
    config.value = typeof c === 'string' ? null : c
    groups.value = g
    selectedGroups.value = d.groups.map((x) => x.id)
  }

  /** Actions offered for the device's state and the user's role (approve and release: operators too). */
  const actions = computed<DeviceAction[]>(() =>
    device.value
      ? actionsFor(device.value.state).filter((a) =>
          a === 'approve' || a === 'release-quarantine' ? session.canWrite : session.canDelete,
        )
      : [],
  )

  function confirmation(action: DeviceAction, hostname: string): ConfirmOptions {
    const base = {
      title: t('devices.actions.' + action + '.title'),
      message: t('devices.actions.' + action + '.confirm', { hostname }),
      confirmLabel: t('devices.actions.' + action + '.label'),
    }
    switch (action) {
      case 'retire':
        return { ...base, destructive: true, requireTypedText: hostname }
      case 'reject':
        return { ...base, destructive: true }
      default:
        return base
    }
  }

  async function run(action: DeviceAction): Promise<void> {
    if (!device.value) return
    problem.value = ''
    if (!(await confirm(confirmation(action, device.value.hostname)))) return
    problem.value = (await runDeviceAction(device.value.id, action)) ?? ''
    await load()
  }

  async function saveGroups(): Promise<void> {
    if (!device.value) return
    problem.value = ''
    saved.value = false
    problem.value = (await setDeviceGroups(device.value.id, selectedGroups.value)) ?? ''
    saved.value = !problem.value
    await load()
  }

  return { device, config, groups, selectedGroups, problem, saved, actions, load, run, saveGroups }
}
