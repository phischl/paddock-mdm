// Scenario checkin (plan M6b decision 1, N1): RATE check-ins per second (default 1 000) against one gateway replica;
// p99 < 200 ms and an error rate < 0.1 % in the measured phase after a warm-up.
import { check } from 'k6'
import exec from 'k6/execution'
import { ownDevices, seconds, signedRequest } from './lib.js'

const rate = Number(__ENV.RATE || 1000)
const vus = Number(__ENV.VUS || 400)
const warmup = __ENV.WARMUP || '1m'
const duration = __ENV.DURATION || '5m'

// One scenario, so that every device stays with one VU (its sequence number lives there); requests carry the tag
// phase=warmup during the ramp and phase=measure afterwards, and only the measured phase has thresholds.
export const options = {
  scenarios: {
    checkin: {
      executor: 'ramping-arrival-rate', startRate: Math.ceil(rate / 10), timeUnit: '1s', preAllocatedVUs: vus, maxVUs: vus,
      stages: [{ target: rate, duration: warmup }, { target: rate, duration }],
    },
  },
  thresholds: {
    'http_req_duration{phase:measure}': ['p(99)<200'],
    'http_req_failed{phase:measure}': ['rate<0.001'],
    'checks{phase:measure}': ['rate>0.999'],
  },
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
}

let devices
let next = 0

export default async function () {
  if (!devices) devices = await ownDevices(vus)
  const dev = devices[next++ % devices.length]
  const phase = Date.now() - exec.scenario.startTime < seconds(warmup) * 1000 ? 'warmup' : 'measure'
  const res = await signedRequest(dev, 'POST', '/v1/checkin', {
    applied_bundle_version: dev.applied, agent_version: '0.0.0-load', schema_versions: [1, 2], health: { reconcile: 'ok' }, arch: 'amd64',
  }, { name: 'checkin', phase })
  const ok = check(res, { 'check-in 200': (r) => r.status === 200 }, { phase })
  if (!ok) return
  dev.seq = res.json('seq')
  // Steady state (N1): a device reports the bundle it was offered as applied, so later check-ins carry no bundle.
  const offered = res.json('bundle.version')
  if (offered) dev.applied = offered
}
