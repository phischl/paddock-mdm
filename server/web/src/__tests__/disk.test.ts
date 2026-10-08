import { describe, expect, it } from 'vitest'
import { diskStateFilter, diskStates, headerDevice, headerFileName, latestStored, volumeHeaders } from '../lib/disk'
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

  it('assigns the header generations to their volumes; those without a volume are the root volume\'s (PDK-009)', () => {
    const at = '2026-10-06T10:00:00Z'
    const root = { uuid: 'r', device: '/dev/sda3', root: true, keyslots: 2, tokens: [], escrowed: true }
    const data = { uuid: 'd', device: '/dev/sdb1', root: false, keyslots: 1, tokens: [], escrowed: true }
    const headers = [
      { generation: 4, status: 'stored' as const, created_at: at, volume: 'd' },
      { generation: 3, status: 'stored' as const, created_at: at, volume: 'r' },
      { generation: 1, status: 'stored' as const, created_at: at },
    ]
    expect(volumeHeaders(headers, root).map((h) => h.generation)).toEqual([3, 1])
    expect(volumeHeaders(headers, data).map((h) => h.generation)).toEqual([4])
    expect(headers.map((h) => headerDevice(h, [root, data]))).toEqual(['/dev/sdb1', '/dev/sda3', '/dev/sda3'])
  })

  it('filters by every state, each with a label', () => {
    expect(diskStateFilter.kind === 'enum' && diskStateFilter.options.map((o) => o.value)).toEqual(diskStates)
    for (const s of diskStates) expect(en.devices.disk.states[s]).toBeTruthy()
  })
})
