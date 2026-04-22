// Mixed-traffic k6 scenario against the pycoraza shared example contract.
// Ported from coraza-node/bench/k6/mixed.js. Designed to approximate realistic
// app traffic so the WAF overhead number we report is meaningful (not a
// happy-path synthetic).
//
// Run:
//   TARGET_URL=http://127.0.0.1:8001 k6 run bench/k6/mixed.js
//
// Env vars:
//   TARGET_URL    target server (default http://127.0.0.1:8001)
//                 BASE_URL is also accepted for coraza-node compatibility
//   VUS           virtual users (default 50)
//   DURATION      test duration (default 20s)
//   SCENARIO      single | mixed — default mixed
//
// Traffic mix: ~70% happy path, ~30% attack payloads. Attacks are tagged so
// the script can tell "returned 200 and should have been blocked" apart from
// "returned 4xx as expected". bench/k6_run.py fails the build when
// missed_attacks > 0.

import http from 'k6/http'
import { check } from 'k6'
import { Trend, Counter } from 'k6/metrics'

const BASE = __ENV.TARGET_URL || __ENV.BASE_URL || 'http://127.0.0.1:8001'
const VUS = parseInt(__ENV.VUS || '50', 10)
const DURATION = __ENV.DURATION || '20s'

export const options = {
  vus: VUS,
  duration: DURATION,
  thresholds: {
    // p(99) under 500 ms even with WAF+CRS — sanity ceiling, not a product SLO.
    http_req_duration: ['p(99)<500'],
    // < 1% unexpected failures on benign traffic.
    checks: ['rate>0.99'],
    // Hard fail if any attack slips through while WAF is engaged.
    missed_attacks: ['count==0'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
}

// Per-route latency trends — helpful when diagnosing which path regressed.
const trends = {
  root: new Trend('route_root', true),
  healthz: new Trend('route_healthz', true),
  search: new Trend('route_search', true),
  echo: new Trend('route_echo', true),
  upload: new Trend('route_upload', true),
  image: new Trend('route_image', true),
  user: new Trend('route_user', true),
  attackSqli: new Trend('route_attack_sqli', true),
  attackXss: new Trend('route_attack_xss', true),
  attackTraversal: new Trend('route_attack_traversal', true),
  attackCmdi: new Trend('route_attack_cmdi', true),
}

const blocked = new Counter('blocked_attacks')
const missedAttacks = new Counter('missed_attacks')

const xssBody = JSON.stringify({ msg: '<script>alert(1)</script>' })
const cmdiBody = JSON.stringify({ msg: '; cat /etc/passwd', cmd: '`id`' })
const benignBody = JSON.stringify({ msg: 'hello', userId: 42 })
const uploadBody = 'x'.repeat(1024)

// Weights roughly reflect real apps — most traffic is benign reads, a
// minority are writes, attacks are rare. Sum doesn't need to be 100.
const scenarios = [
  { weight: 25, fn: rootReq },
  { weight: 25, fn: searchReq },
  { weight: 10, fn: healthzReq },
  { weight: 10, fn: userReq },
  { weight: 10, fn: echoReq },
  { weight: 5, fn: uploadReq },
  { weight: 5, fn: imageReq },
  // ~10% attacks, distributed across SQLi/XSS/path-traversal/command-injection.
  { weight: 3, fn: sqliAttack },
  { weight: 3, fn: xssAttack },
  { weight: 2, fn: traversalAttack },
  { weight: 2, fn: cmdiAttack },
]
const totalWeight = scenarios.reduce((s, x) => s + x.weight, 0)

export default function () {
  const forced = __ENV.SCENARIO
  if (forced === 'single') {
    rootReq()
    return
  }
  let r = Math.random() * totalWeight
  for (const s of scenarios) {
    r -= s.weight
    if (r <= 0) {
      s.fn()
      return
    }
  }
}

function rootReq() {
  const r = http.get(`${BASE}/`)
  trends.root.add(r.timings.duration)
  check(r, { 'root 200': (x) => x.status === 200 })
}

function healthzReq() {
  const r = http.get(`${BASE}/healthz`)
  trends.healthz.add(r.timings.duration)
  check(r, { 'healthz 200': (x) => x.status === 200 })
}

function searchReq() {
  const r = http.get(`${BASE}/search?q=hello+world`)
  trends.search.add(r.timings.duration)
  check(r, { 'search 200': (x) => x.status === 200 })
}

function echoReq() {
  const r = http.post(`${BASE}/echo`, benignBody, {
    headers: { 'content-type': 'application/json' },
  })
  trends.echo.add(r.timings.duration)
  check(r, { 'echo 200': (x) => x.status === 200 })
}

function uploadReq() {
  const r = http.post(`${BASE}/upload`, uploadBody, {
    headers: { 'content-type': 'application/octet-stream' },
  })
  trends.upload.add(r.timings.duration)
  check(r, { 'upload 2xx': (x) => x.status >= 200 && x.status < 300 })
}

function imageReq() {
  const r = http.get(`${BASE}/img/logo.png`)
  trends.image.add(r.timings.duration)
  check(r, { 'image 200': (x) => x.status === 200 })
}

function userReq() {
  const r = http.get(`${BASE}/api/users/42`)
  trends.user.add(r.timings.duration)
  check(r, { 'user 200': (x) => x.status === 200 })
}

// --- attack payloads. Each tag is a payload the WAF MUST block with CRS. ---

function sqliAttack() {
  const q = encodeURIComponent("' OR 1=1-- -")
  const r = http.get(`${BASE}/search?q=${q}`, { tags: { attack: 'sqli' } })
  trends.attackSqli.add(r.timings.duration)
  recordAttack(r)
}

function xssAttack() {
  const r = http.post(`${BASE}/echo`, xssBody, {
    headers: { 'content-type': 'application/json' },
    tags: { attack: 'xss' },
  })
  trends.attackXss.add(r.timings.duration)
  recordAttack(r)
}

function traversalAttack() {
  const r = http.get(`${BASE}/api/users/..%2F..%2F..%2Fetc%2Fpasswd`, {
    tags: { attack: 'traversal' },
  })
  trends.attackTraversal.add(r.timings.duration)
  recordAttack(r)
}

function cmdiAttack() {
  const r = http.post(`${BASE}/echo`, cmdiBody, {
    headers: { 'content-type': 'application/json' },
    tags: { attack: 'cmdi' },
  })
  trends.attackCmdi.add(r.timings.duration)
  recordAttack(r)
}

// Increment the right counter based on WAF verdict:
//   - 403 (or any 4xx): counted as blocked.
//   - 2xx: counted as MISSED — the WAF let it through. That's a regression.
//   - 5xx / network errors: not counted — they're infra issues, not verdicts.
function recordAttack(r) {
  if (r.status === 403) {
    blocked.add(1)
  } else if (r.status >= 200 && r.status < 300) {
    missedAttacks.add(1)
  } else if (r.status >= 400 && r.status < 500) {
    blocked.add(1)
  }
}
