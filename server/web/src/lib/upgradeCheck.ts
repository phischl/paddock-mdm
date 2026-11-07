import { api, problemCode } from '../api/client'
import type { components } from '../api/schema'
import type { Status } from './status'

/** The read-only upgrade report of the server (plan M16 decision 4, ADR 0047). */
export type UpgradeCheck = components['schemas']['UpgradeCheck']
export type UpgradeCheckItem = components['schemas']['UpgradeCheckItem']

/** The report for the release the server runs: its support window, the agents outside it, the backup state. */
export async function getUpgradeCheck(targetVersion: string): Promise<UpgradeCheck | string> {
  const { data, error } = await api.GET('/api/platform/v1/upgrade-check', {
    params: { query: { target_version: targetVersion } },
  })
  return data ?? problemCode(error)
}

/** One item of the report by name; the report always lists all six, a missing one is simply not shown. */
export function upgradeItem(report: UpgradeCheck, name: UpgradeCheckItem['name']): UpgradeCheckItem | undefined {
  return report.items.find((i) => i.name === name)
}

/** The chip status of an item: PASS ok, WARN warn, FAIL critical, INFO info. */
export function upgradeItemStatus(item: UpgradeCheckItem): Status {
  switch (item.status) {
    case 'PASS':
      return 'ok'
    case 'WARN':
      return 'warn'
    case 'FAIL':
      return 'critical'
    default:
      return 'info'
  }
}
