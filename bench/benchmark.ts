/**
 * Comparative micro-benchmark: permzplus vs CASL vs accesscontrol.
 *
 * Run with:  pnpm bench:compare
 *
 * Tests the hot path: a single `.can()` / `.can()` / `.can()` call for a
 * role that already exists in each library's internal store. Each library is
 * warmed up before timing starts so V8's JIT sees optimised machine code.
 *
 * Results are printed as an Operations-per-Second table by mitata.
 */
import { run, bench, group, summary } from 'mitata'

// ---------------------------------------------------------------------------
// permzplus
// ---------------------------------------------------------------------------
import { PolicyEngine } from '../src/policy'

const pz = new PolicyEngine()
pz.addRole({ name: 'VIEWER', level: 1, permissions: ['posts:read', 'comments:read'] })
pz.addRole({ name: 'EDITOR', level: 2, permissions: ['posts:write', 'posts:delete', 'comments:write'] })
pz.addRole({ name: 'ADMIN',  level: 3, permissions: ['*'] })

// Warm up — populates permCache + permBitsCache + checkCache.
pz.can('ADMIN',  'posts:delete')
pz.can('VIEWER', 'posts:read')
pz.can('EDITOR', 'posts:write')
pz.can('VIEWER', 'posts:delete')  // false path

// ---------------------------------------------------------------------------
// CASL — @casl/ability
// ---------------------------------------------------------------------------
import { AbilityBuilder, createMongoAbility, type MongoAbility } from '@casl/ability'

function buildCaslAbility(role: string): MongoAbility {
  const { can, build } = new AbilityBuilder(createMongoAbility)
  if (role === 'VIEWER') {
    can('read', 'Post')
    can('read', 'Comment')
  } else if (role === 'EDITOR') {
    can('read',   'Post')
    can('write',  'Post')
    can('delete', 'Post')
    can('write',  'Comment')
  } else if (role === 'ADMIN') {
    can('manage', 'all')
  }
  return build()
}

const caslAdmin  = buildCaslAbility('ADMIN')
const caslEditor = buildCaslAbility('EDITOR')
const caslViewer = buildCaslAbility('VIEWER')

// ---------------------------------------------------------------------------
// accesscontrol
// ---------------------------------------------------------------------------
import { AccessControl } from 'accesscontrol'

const ac = new AccessControl()
ac.grant('VIEWER').readAny('Post').readAny('Comment')
ac.grant('EDITOR').extend('VIEWER').createAny('Post').updateAny('Post').deleteAny('Post').createAny('Comment')
ac.grant('ADMIN').extend('EDITOR').createAny('all').readAny('all').updateAny('all').deleteAny('all')

// ---------------------------------------------------------------------------
// Benchmarks — grouped by scenario
// ---------------------------------------------------------------------------

summary(() => {

  group('read — allowed (VIEWER can read Post)', () => {
    bench('permzplus', () => {
      pz.can('VIEWER', 'posts:read')
    })

    bench('CASL', () => {
      caslViewer.can('read', 'Post')
    })

    bench('accesscontrol', () => {
      ac.can('VIEWER').readAny('Post').granted
    })
  })

  group('write — allowed (EDITOR can write Post)', () => {
    bench('permzplus', () => {
      pz.can('EDITOR', 'posts:write')
    })

    bench('CASL', () => {
      caslEditor.can('write', 'Post')
    })

    bench('accesscontrol', () => {
      ac.can('EDITOR').updateAny('Post').granted
    })
  })

  group('delete — allowed via wildcard (ADMIN)', () => {
    bench('permzplus', () => {
      pz.can('ADMIN', 'posts:delete')
    })

    bench('CASL', () => {
      caslAdmin.can('delete', 'Post')
    })

    bench('accesscontrol', () => {
      ac.can('ADMIN').deleteAny('Post').granted
    })
  })

  group('read — denied (VIEWER cannot delete Post)', () => {
    bench('permzplus', () => {
      pz.can('VIEWER', 'posts:delete')
    })

    bench('CASL', () => {
      caslViewer.can('delete', 'Post')
    })

    bench('accesscontrol', () => {
      ac.can('VIEWER').deleteAny('Post').granted
    })
  })

})

// ---------------------------------------------------------------------------
// Throughput test — 1 000 000 iterations
// ---------------------------------------------------------------------------

bench('1_000_000 × permzplus.can (ADMIN, posts:read)', () => {
  for (let i = 0; i < 1_000_000; i++) pz.can('ADMIN', 'posts:read')
})

bench('1_000_000 × CASL.can (ADMIN, read Post)', () => {
  for (let i = 0; i < 1_000_000; i++) caslAdmin.can('read', 'Post')
})

bench('1_000_000 × accesscontrol.can (ADMIN, readAny Post)', () => {
  for (let i = 0; i < 1_000_000; i++) ac.can('ADMIN').readAny('Post').granted
})

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

void run({
  colors:      true,
  avg:         true,
  min_max:     true,
  percentiles: false,
})
