import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { DeviceDetail, EffectiveConfig, EffectiveSudo, User, UserGroup } from '../api/client'
import { useConfirm, type ConfirmOptions } from '../composables/useConfirm'
import {
  actionsFor, allGroups, getDevice, getEffectiveConfig, runDeviceAction, setDeviceGroups, setLoginAssignment,
  setLoginsSuspended, type DeviceAction,
} from './devices'
import { getEffectiveSudo } from './profiles'
import { allUserGroups } from './userGroups'
import { allUsers } from './users'
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
  const users = ref<User[]>([])
  const userGroups = ref<UserGroup[]>([])
  const loginUsers = ref<string[]>([])
  const loginGroups = ref<string[]>([])
  const loginSaved = ref(false)
  const sudo = ref<EffectiveSudo | null>(null)

  async function load(): Promise<void> {
    const [d, c, g, s] = await Promise.all([getDevice(id()), getEffectiveConfig(id()), allGroups(), getEffectiveSudo(id())])
    if (typeof d === 'string') {
      problem.value = d
      return
    }
    device.value = d
    config.value = typeof c === 'string' ? null : c
    groups.value = g
    selectedGroups.value = d.groups.map((x) => x.id)
    loginUsers.value = d.login_assignment.users.map((u) => u.id)
    loginGroups.value = d.login_assignment.groups.map((x) => x.id)
    sudo.value = typeof s === 'string' ? null : s
  }

  /** Users and groups for the login assignment (writers only). */
  async function loadSubjects(): Promise<void> {
    if (!session.canWrite) return
    const [u, g] = await Promise.all([allUsers(), allUserGroups()])
    users.value = u
    userGroups.value = g
  }

  async function saveLogin(): Promise<void> {
    if (!device.value) return
    problem.value = ''
    loginSaved.value = false
    problem.value = (await setLoginAssignment(device.value.id, loginUsers.value, loginGroups.value)) ?? ''
    loginSaved.value = !problem.value
    await load()
  }

  /** Suspends or resumes directory logins after a confirmation (security-relevant, ADR 0018). */
  async function toggleSuspension(): Promise<void> {
    if (!device.value) return
    const d = device.value
    const suspend = !d.logins_suspended
    const key = suspend ? 'devices.login.suspend' : 'devices.login.resume'
    const confirmed = await confirm({
      title: t(key + '.title'), message: t(key + '.confirm', { hostname: d.hostname }), confirmLabel: t(key + '.label'),
      destructive: suspend,
    })
    if (!confirmed) return
    problem.value = (await setLoginsSuspended(d.id, suspend)) ?? ''
    await load()
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

  return {
    device, config, groups, selectedGroups, problem, saved, actions, load, run, saveGroups,
    users, userGroups, loginUsers, loginGroups, loginSaved, sudo, loadSubjects, saveLogin, toggleSuspension,
  }
}
