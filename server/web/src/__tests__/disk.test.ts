import { describe, expect, it } from 'vitest'
import { diskStateFilter, diskStates, headerFileName, latestStored } from '../lib/disk'
import en from '../locales/en.json'

describe('disk encryption', () => {
  it('names the downloaded header after the Content-Disposition of the server', () => {
    expect(headerFileName('attachment; filename=laptop-1-luks-header-3.img', 'laptop-1')).toBe('laptop-1-luks-header-3.img')
    expect(headerFileName('attachment; filename="odd host-luks-header-2.img"', 'odd host')).toBe('odd host-luks-header-2.img')
    expect(headerFileName(null, 'laptop-1')).toBe('laptop-1-luks-header.img')
  })

  it('takes the newest stored generation', () => {
    const at = '2026-10-06T10:00:00Z'
    expect(latestStored([
      { generation: 3, status: 'pending', created_at: at },
      { generation: 2, status: 'stored', created_at: at },
      { generation: 1, status: 'stored', created_at: at },
    ])?.generation).toBe(2)
    expect(latestStored([{ generation: 1, status: 'failed', created_at: at }])).toBeNull()
  })

  it('filters by every state, each with a label', () => {
    expect(diskStateFilter.kind === 'enum' && diskStateFilter.options.map((o) => o.value)).toEqual(diskStates)
    for (const s of diskStates) expect(en.devices.disk.states[s]).toBeTruthy()
  })
})
