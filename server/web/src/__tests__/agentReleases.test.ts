import { describe, expect, it } from 'vitest'
import { rolloutActionsFor } from '../lib/agentReleases'
import type { AgentReleaseDetail } from '../api/client'

const detail = (status: 'draft' | 'published', rollout?: 'running' | 'halted' | 'completed'): AgentReleaseDetail => ({
  release: { version: '1.2.0', status, created_by: 'root', created_at: '2026-10-04T10:00:00Z', artifact_count: 1 },
  artifacts: [],
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
