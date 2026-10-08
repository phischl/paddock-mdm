// Device request signing for the k6 load scenarios (architecture §6.3), with k6's WebCrypto: ECDSA P-256 over
// SHA-256 of the canonical string. WebCrypto returns the signature as r‖s (IEEE P1363); the gateway verifies ASN.1
// DER (ecdsa.VerifyASN1), so it is converted here.
import http from 'k6/http'
import { SharedArray } from 'k6/data'
import { b64decode, b64encode } from 'k6/encoding'

/** The identities written by test/load/cmd/identities (IDENTITIES, default identities.json). */
export const identities = new SharedArray('identities', () => JSON.parse(open(__ENV.IDENTITIES || 'identities.json')))

/** The device API base URL, e.g. http://paddock-gateway:8081 for one gateway replica. */
export const baseURL = (__ENV.GATEWAY_URL || 'http://paddock-gateway:8081').replace(/\/$/, '')

function ascii(s) {
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c > 0x7f) throw new Error('only ASCII is signed by the load scenarios')
    out[i] = c
  }
  return out
}

function derInteger(bytes) {
  let i = 0
  while (i < bytes.length - 1 && bytes[i] === 0) i++
  const v = bytes.slice(i)
  return v[0] & 0x80 ? [0x02, v.length + 1, 0, ...v] : [0x02, v.length, ...v]
}

/** The ASN.1 DER ECDSA signature of a 64-byte P1363 signature r‖s. */
export function p1363ToDER(sig) {
  const raw = new Uint8Array(sig)
  const body = [...derInteger(raw.slice(0, 32)), ...derInteger(raw.slice(32, 64))]
  return new Uint8Array([0x30, body.length, ...body]).buffer
}

/** The seconds of a k6 duration such as 90s or 5m. */
export function seconds(d) {
  const m = /^(\d+)(s|m)$/.exec(d)
  if (!m) throw new Error(`duration ${d}: use <n>s or <n>m`)
  return Number(m[1]) * (m[2] === 'm' ? 60 : 1)
}

/**
 * The devices of this VU: of the `vus` VUs of the scenario (k6 numbers them consecutively), the VU with ID n owns
 * every identity i with i % vus == n % vus, so that each device is driven by exactly one VU and its sequence number,
 * which only that VU knows, stays consistent.
 */
export async function ownDevices(vus) {
  const own = []
  for (let i = __VU % vus; i < identities.length; i += vus) {
    const id = identities[i]
    const key = await crypto.subtle.importKey('pkcs8', b64decode(id.key_pkcs8, 'std'), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
    own.push({ id: id.device_id, keyID: id.key_id, ip: id.ip || '', key, seq: 0, applied: 0, eventSeq: Date.now() * 1000 })
  }
  if (own.length === 0) throw new Error(`VU ${__VU} owns no device: use at least as many identities as VUs`)
  return own
}

/** Sends a signed device request with JSON body (or none) and returns the k6 response. */
export async function signedRequest(dev, method, path, body, tags) {
  const payload = body === undefined ? '' : JSON.stringify(body)
  const contentSHA = b64encode(await crypto.subtle.digest('SHA-256', ascii(payload)), 'rawurl')
  const nonce = b64encode(crypto.getRandomValues(new Uint8Array(16)).buffer, 'rawurl')
  const ts = String(Math.floor(Date.now() / 1000))
  const seq = String(dev.seq)
  const canonical = ['paddock-v1', method, path, dev.id, dev.keyID, ts, nonce, contentSHA, seq].join('\n')
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, dev.key, ascii(canonical))
  const headers = {
    'Paddock-Device': dev.id,
    'Paddock-Key-Id': dev.keyID,
    'Paddock-Timestamp': ts,
    'Paddock-Nonce': nonce,
    'Paddock-Content-SHA256': contentSHA,
    'Paddock-Seq': seq,
    'Paddock-Signature': b64encode(p1363ToDER(sig), 'rawurl'),
  }
  if (payload !== '') headers['Content-Type'] = 'application/json'
  // Only honoured when the scenario talks to the gateway directly (no edge in front): a fleet has many addresses,
  // the gateway's per-IP limit would otherwise throttle the single load generator.
  if (dev.ip) headers['X-Forwarded-For'] = dev.ip
  return http.asyncRequest(method, baseURL + path, payload === '' ? null : payload, { headers, tags })
}
