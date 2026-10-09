// Scenario ingest (plan M6b decision 1, N2): EVENTS_PER_S device events per second (default 5 000, in batches of
// BATCH events per request, one queue message each) through the gateway while 3 worker replicas consume them; the
// consumer lag of the queue ingest.event stays below 60 s. A second scenario reads the queue's backlog from the
// Prometheus of the observability profile (PROMETHEUS_URL, rabbitmq_detailed_queue_messages) every 5 s and keeps
// sampling for DRAIN after the load ends, so a backlog that never clears fails the run. The lag is the backlog
// divided by the consumption rate (published messages minus the backlog's growth); while nothing is consumed it is
// the time since the backlog was last empty. Prometheus scrapes every SCRAPE_INTERVAL_S (15 s), so the figure has that
// resolution and the consumption is derived over at least one scrape interval.
import http from 'k6/http'
import { check, sleep } from 'k6'
import { Trend } from 'k6/metrics'
import exec from 'k6/execution'
import { ownDevices, seconds, signedRequest } from './lib.js'

const eventsPerSecond = Number(__ENV.EVENTS_PER_S || 5000)
const batch = Number(__ENV.BATCH || 50)
const vus = Number(__ENV.VUS || 200)
const duration = __ENV.DURATION || '5m'
const drain = __ENV.DRAIN || '2m'
const prometheus = (__ENV.PROMETHEUS_URL || 'http://prometheus:9090').replace(/\/$/, '')
const scrapeSeconds = Number(__ENV.SCRAPE_INTERVAL_S || 15)
const messagesPerSecond = Math.ceil(eventsPerSecond / batch)

const lagSeconds = new Trend('ingest_consumer_lag_seconds')
const backlog = new Trend('ingest_backlog_messages')
const auditBacklog = new Trend('audit_writer_backlog_messages')

export const options = {
  scenarios: {
    events: {
      executor: 'constant-arrival-rate', rate: messagesPerSecond, timeUnit: '1s', duration,
      preAllocatedVUs: vus, maxVUs: vus, exec: 'events',
    },
    lag: {
      executor: 'constant-vus', vus: 1, duration: `${seconds(duration) + seconds(drain)}s`, exec: 'sampleLag',
    },
  },
  thresholds: {
    'http_req_failed{scenario:events}': ['rate<0.001'],
    'checks{scenario:events}': ['rate>0.999'],
    ingest_consumer_lag_seconds: ['max<60'],
  },
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max'],
}

let devices
let next = 0

export async function events() {
  if (!devices) devices = await ownDevices(vus)
  const dev = devices[next++ % devices.length]
  const now = new Date().toISOString()
  const list = []
  for (let i = 0; i < batch; i++) {
    list.push({ event_seq: dev.eventSeq++, type: 'config.drift_corrected', occurred_at: now, data: { resource: 'file:/etc/paddock-load.conf' } })
  }
  const res = await signedRequest(dev, 'POST', '/v1/events', { events: list }, { name: 'events' })
  check(res, { 'events 202': (r) => r.status === 202 })
}

function backlogOf(queue) {
  const res = http.get(`${prometheus}/api/v1/query?query=${encodeURIComponent(`sum(rabbitmq_detailed_queue_messages{queue="${queue}"})`)}`, {
    tags: { name: 'prometheus' },
  })
  const result = res.status === 200 ? res.json('data.result') : null
  // Without the backlog the run proves nothing about N2: stop it.
  if (!result || result.length !== 1) exec.test.abort(`Prometheus: no backlog of ${queue} (HTTP ${res.status})`)
  return Number(result[0].value[1])
}

const samples = []
let emptySince = Date.now()

export function sampleLag() {
  const now = Date.now()
  const depth = backlogOf('ingest.event')
  backlog.add(depth)
  auditBacklog.add(backlogOf('audit.writer'))
  if (depth === 0) emptySince = now
  // Two samples of the same scrape show no change although the queue moved, which would count as nothing consumed:
  // compare with the newest sample at least one scrape interval old.
  const ref = samples.filter((s) => now - s.at >= scrapeSeconds * 1000).pop()
  if (ref) {
    const dt = (now - ref.at) / 1000
    const start = exec.scenario.startTime
    const end = start + seconds(duration) * 1000
    const publishedS = Math.max(0, Math.min(now, end) - Math.max(ref.at, start)) / 1000
    const consumed = (messagesPerSecond * publishedS - (depth - ref.depth)) / dt
    lagSeconds.add(depth === 0 ? 0 : consumed > 0 ? depth / consumed : (now - emptySince) / 1000)
  }
  samples.push({ at: now, depth })
  sleep(5)
}
