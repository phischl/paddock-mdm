import { describe, expect, it } from 'vitest'
import { importableVersion, rolloutActionsFor, sourcePanelState } from '../lib/agentReleases'
import type { AgentReleaseCheck, AgentReleaseDetail, AgentReleaseSource } from '../api/client'

const detail = (status: 'draft' | 'published', rollout?: 'running' | 'halted' | 'completed'): AgentReleaseDetail => ({
  release: { version: '1.2.0', status, created_by: 'root', created_at: '2026-10-04T10:00:00Z', artifact_count: 1 },
  artifacts: [],
  packages: [],
  rollout: rollout && {
    version: '1.2.0', waves: [1, 10, 50, 100], current_wave_index: 0, wave_started_at: '2026-10-04T10:00:00Z',
    min_wave_minutes: 1440, failure_threshold_percent: 2, failure_threshold_min: 3, status: rollout,
    started_by: 'root', started_at: '2026-10-04T10:00:00Z',
  },
})

describe('agent release rollout actions', () => {
  it('offers only the transitions of the release and rollout state', () => {
    expect(rolloutActionsFor(detail('draft'))).toEqual([])
    expect(rolloutActionsFor(detail('published'))).toEqual(['start'])
    expect(rolloutActionsFor(detail('published', 'running'))).toEqual(['halt'])
    expect(rolloutActionsFor(detail('published', 'halted'))).toEqual(['resume'])
    expect(rolloutActionsFor(detail('published', 'completed'))).toEqual([])
  })
})

const enabled: AgentReleaseSource = { enabled: true, repository: 'phischl/paddock-mdm', url: 'https://api.github.com' }
const newer: AgentReleaseCheck = {
  latest: '0.1.0-alpha.6', published_at: '2026-10-25T10:00:00Z', newest_stored: '0.1.0-alpha.5', importable: true,
  reason: null,
}
const notNewer: AgentReleaseCheck = { ...newer, latest: '0.1.0-alpha.5', importable: false, reason: 'not_newer' }
const noneFound: AgentReleaseCheck = {
  latest: null, published_at: null, newest_stored: '0.1.0-alpha.5', importable: false, reason: 'none_found',
}

describe('agent release source panel', () => {
  it('is hidden while the source is not loaded, failed or switched off', () => {
    expect(sourcePanelState(null, null)).toEqual({ kind: 'hidden' })
    expect(sourcePanelState('forbidden', newer)).toEqual({ kind: 'hidden' })
    expect(sourcePanelState({ enabled: false, repository: null, url: null }, null)).toEqual({ kind: 'hidden' })
    expect(sourcePanelState({ enabled: false, repository: null, url: null }, newer)).toEqual({ kind: 'hidden' })
  })

  it('is idle with the repository before a check', () => {
    expect(sourcePanelState(enabled, null)).toEqual({ kind: 'idle', repository: 'phischl/paddock-mdm' })
  })

  it('shows the check after a check', () => {
    expect(sourcePanelState(enabled, newer)).toEqual({ kind: 'checked', repository: 'phischl/paddock-mdm', check: newer })
  })

  it('offers the import only for an importable check', () => {
    expect(importableVersion(sourcePanelState(enabled, newer))).toBe('0.1.0-alpha.6')
    expect(importableVersion(sourcePanelState(enabled, notNewer))).toBeNull()
    expect(importableVersion(sourcePanelState(enabled, noneFound))).toBeNull()
    expect(importableVersion(sourcePanelState(enabled, null))).toBeNull()
    expect(importableVersion(sourcePanelState({ enabled: false, repository: null, url: null }, newer))).toBeNull()
  })
})
