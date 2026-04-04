/**
 * Hot-path micro-benchmark: permzplus.can() vs a plain if/else.
 *
 * Run with:  pnpm bench
 *
 * Uses mitata for stable, low-noise timing with warm-up iterations
 * so V8's JIT has time to fully optimise both paths.
 */
import { run, bench, group } from 'mitata'
import { PolicyEngine } from '../src/policy'

// ---------------------------------------------------------------------------
// Fixture setup — done once outside the timed loop
// ---------------------------------------------------------------------------

const policy = new PolicyEngine()

policy.addRole({ name: 'VIEWER', level: 1, permissions: ['posts:read', 'comments:read'] })
policy.addRole({ name: 'EDITOR', level: 2, permissions: ['posts:write', 'comments:write'] })
policy.addRole({ name: 'ADMIN',  level: 3, permissions: ['*'] })

// Pre-warm the permission cache so the first benchmark iteration doesn't
// include a cold-cache penalty.
policy.can('ADMIN', 'posts:delete')
policy.can('VIEWER', 'posts:read')
policy.can('EDITOR', 'posts:write')

// Reference baseline: equivalent hand-written if/else.
const VIEWER_PERMS = new Set(['posts:read', 'comments:read'])
const EDITOR_PERMS = new Set(['posts:write', 'comments:write', 'posts:read', 'comments:read'])
const ALL = true

function baselineCheck(role: string, permission: string): boolean {
  if (role === 'ADMIN') return ALL
  if (role === 'EDITOR') return EDITOR_PERMS.has(permission)
  if (role === 'VIEWER') return VIEWER_PERMS.has(permission)
  return false
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

group('can() — cache hit (hot path)', () => {
  bench('permzplus.can (ADMIN, posts:delete)', () => {
    policy.can('ADMIN', 'posts:delete')
  })

  bench('baseline if/else (ADMIN, posts:delete)', () => {
    baselineCheck('ADMIN', 'posts:delete')
  })
})

group('can() — VIEWER read permission', () => {
  bench('permzplus.can (VIEWER, posts:read)', () => {
    policy.can('VIEWER', 'posts:read')
  })

  bench('baseline if/else (VIEWER, posts:read)', () => {
    baselineCheck('VIEWER', 'posts:read')
  })
})

group('can() — denied permission', () => {
  bench('permzplus.can (VIEWER, posts:delete) → false', () => {
    policy.can('VIEWER', 'posts:delete')
  })

  bench('baseline if/else (VIEWER, posts:delete) → false', () => {
    baselineCheck('VIEWER', 'posts:delete')
  })
})

// ---------------------------------------------------------------------------
// 1 000 000-iteration aggregate (validates throughput claim)
// ---------------------------------------------------------------------------

bench('1_000_000 × permzplus.can (ADMIN, posts:read)', () => {
  for (let i = 0; i < 1_000_000; i++) {
    policy.can('ADMIN', 'posts:read')
  }
})

bench('1_000_000 × baseline if/else (ADMIN, posts:read)', () => {
  for (let i = 0; i < 1_000_000; i++) {
    baselineCheck('ADMIN', 'posts:read')
  }
})

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

await run({ colors: true, avg: true, min_max: true, percentiles: true })
