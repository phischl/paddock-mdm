import { beforeEach, describe, expect, it, vi } from 'vitest'

const calls = vi.hoisted(() => ({ query: [] as unknown[] }))
vi.mock('../api/client', async (original) => {
  const respond = (params: { query?: unknown }) => {
    calls.query.push(params.query)
    return Promise.resolve({ data: {}, error: undefined })
  }
  return {
    ...(await original<typeof import('../api/client')>()),
    api: { POST: (_: string, o: { params: { query?: unknown } }) => respond(o.params), PATCH: (_: string, o: { params: { query?: unknown } }) => respond(o.params),
      PUT: (_: string, o: { params: { query?: unknown } }) => respond(o.params), DELETE: (_: string, o: { params: { query?: unknown } }) => respond(o.params) },
  }
})

import { deleteManagedUnit, saveManagedFile } from '../lib/managedConfig'
import { deletePackageHold, saveUpdateSettings } from '../lib/updates'
import type { UpdateSettingsUpdate } from '../api/client'

const urgent = { urgent: true, reason: ' hotfix ' }
const file = { groupID: null, path: '/etc/motd', mode: '0644', owner: 'root', group: 'root', content: 'x' }

beforeEach(() => {
  calls.query = []
})

describe('the urgent opt-out reaches the request', () => {
  it('as urgent and the trimmed reason on writes and deletes', async () => {
    await saveManagedFile(null, { ...file, urgent })
    await saveManagedFile('f1', { ...file, urgent })
    await deleteManagedUnit('u1', urgent)
    await deletePackageHold('h1', urgent)
    await saveUpdateSettings({} as UpdateSettingsUpdate, urgent)
    expect(calls.query).toEqual(Array(5).fill({ urgent: true, reason: 'hotfix' }))
  })

  it('as no parameter without the opt-out', async () => {
    await saveManagedFile(null, file)
    await deletePackageHold('h1')
    await saveUpdateSettings({} as UpdateSettingsUpdate, { urgent: false, reason: 'left over' })
    expect(calls.query).toEqual([{}, {}, {}])
  })
})
