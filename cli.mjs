#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
/// <reference types="node" />
/**
 * Concise npm audit: flat table (severity → package → responsible) + grouped counts.
 * Reads JSON from stdin, or runs `npm audit --json` in cwd when stdin is a TTY.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * @param {string} lockPath e.g. `node_modules/foo` or `node_modules/a/node_modules/b`
 * @returns {string | null} package name for that path
 */
function lockPathPackageName(lockPath) {
  const m = lockPath.match(/(?:^|\/)node_modules\/((?:@[^/]+\/[^/]+)|[^/]+)$/)
  return m ? m[1] : null
}

/**
 * Hoisted installs: prefer nested path, then top-level `node_modules/<dep>`.
 * @param {string} parentPath
 * @param {string} depName
 * @param {Record<string, object>} packages
 */
function resolveDependencyPath(parentPath, depName, packages) {
  const nested = `${parentPath}/node_modules/${depName}`
  if (packages[nested]) return nested
  const flat = `node_modules/${depName}`
  if (packages[flat]) return flat
  return null
}

/**
 * Map every package name in the lockfile tree to declared root deps that reach it.
 * Requires lockfile v2+ (`packages`). Used when audit paths omit declared deps (hoisting).
 * @param {string} cwd
 * @param {Set<string>} direct
 * @returns {Map<string, Set<string>>}
 */
function loadLockfileRootMap(cwd, direct) {
  /** @type {Map<string, Set<string>>} */
  const map = new Map()
  let lock
  try {
    lock = JSON.parse(readFileSync(join(cwd, 'package-lock.json'), 'utf8'))
  } catch {
    return map
  }
  const packages = lock.packages
  if (!packages || typeof packages !== 'object' || Number(lock.lockfileVersion) < 2) {
    return map
  }

  /** @type {Array<{ path: string, root: string }>} */
  const queue = []
  const seen = new Set()

  for (const name of direct) {
    const path = `node_modules/${name}`
    if (packages[path]) {
      queue.push({ path, root: name })
      seen.add(path)
    }
  }

  while (queue.length) {
    const item = queue.shift()
    if (!item) break
    const { path, root } = item
    const pkgName = lockPathPackageName(path)
    if (pkgName) {
      let roots = map.get(pkgName)
      if (!roots) {
        roots = new Set()
        map.set(pkgName, roots)
      }
      roots.add(root)
    }

    const entry = packages[path]
    if (!entry || typeof entry !== 'object') continue

    const depKeys = ['dependencies', 'optionalDependencies', 'devDependencies', 'peerDependencies']
    for (const dt of depKeys) {
      const deps = entry[dt]
      if (!deps || typeof deps !== 'object') continue
      for (const depName of Object.keys(deps)) {
        const childPath = resolveDependencyPath(path, depName, packages)
        if (childPath && !seen.has(childPath)) {
          seen.add(childPath)
          queue.push({ path: childPath, root })
        }
      }
    }
  }

  return map
}

/** @param {Set<string> | undefined} s */
function pickOneRoot(s) {
  if (!s || s.size === 0) return null
  return [...s].sort()[0]
}

/** @param {string} cwd */
function loadDirectDeps(cwd) {
  const pkgPath = join(cwd, 'package.json')
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
  return new Set([
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.devDependencies || {}),
    ...Object.keys(pkg.optionalDependencies || {}),
    ...Object.keys(pkg.peerDependencies || {}),
  ])
}

/**
 * Ordered package names along an install path (project root → leaf).
 * Handles scoped packages (`@scope/name`) and Windows separators.
 * @param {string} p
 * @returns {string[]}
 */
function nodeModulesPackageChain(p) {
  if (!p || typeof p !== 'string') return []
  const normalized = p.replace(/\\/g, '/')
  const segments = []
  const re = /(?:^|\/)node_modules\/((?:@[^/]+\/[^/]+)|[^/]+)/g
  let m
  while ((m = re.exec(normalized)) !== null) {
    segments.push(m[1])
  }
  return segments
}

/**
 * @typedef {object} AuditVulnEntry
 * @property {string} [name]
 * @property {{ name?: string }} [fixAvailable]
 * @property {string[]} [nodes]
 * @property {string[]} [effects]
 * @property {boolean} [isDirect]
 */

/**
 * Only names from `direct` (package.json roots) are returned, except "(unresolved)".
 * Uses package-lock.json (v2+) when present to map transitives → a declared root.
 *
 * @param {AuditVulnEntry} v
 * @param {Set<string>} direct
 * @param {Map<string, Set<string>>} pkgToRoot
 * @param {string} pkgName vulnerable package (audit vulnerabilities key)
 * @returns {string}
 */
function rootResponsible(v, direct, pkgToRoot, pkgName) {
  const nodes = v.nodes || []
  /** @type {string[][]} */
  const chains = nodes.map((n) => nodeModulesPackageChain(n)).filter((c) => c.length > 0)

  for (const chain of chains) {
    const directInPath = chain.find((name) => direct.has(name))
    if (directInPath) return directInPath
  }

  const fromLock = pickOneRoot(pkgToRoot.get(pkgName))
  if (fromLock) return fromLock

  const effects = v.effects || []
  const directHit = effects.find((/** @type {string} */ e) => direct.has(e))
  if (directHit) return directHit

  if (v.fixAvailable && typeof v.fixAvailable === 'object' && v.fixAvailable.name) {
    const fixName = v.fixAvailable.name
    if (direct.has(fixName)) return fixName
  }

  if (v.isDirect && pkgName && direct.has(pkgName)) return pkgName
  return '(unresolved)'
}

/** @type {Record<string, number>} */
const severityOrder = { critical: 0, high: 1, info: 4, low: 3, moderate: 2 }

/**
 * @param {string[]} headers
 * @param {string[][]} dataRows
 */
function colWidths(headers, dataRows) {
  return headers.map((h, i) =>
    Math.max(h.length, ...dataRows.map((r) => String(r[i] ?? '').length)),
  )
}

async function main() {
  const argv = process.argv.slice(2)
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`Usage:
  npm-audit-summary              # runs npm audit --json in the current directory
  npm audit --json | npm-audit-summary --stdin
  npm audit --json | npm-audit-summary -

Requires package.json in the current working directory for the "responsible" column.
Uses package-lock.json (when present) to map transitives to a declared dependency.

Options:
  --stdin, -   Read audit JSON from stdin instead of running npm audit.`)
    process.exit(0)
  }

  const cwd = process.cwd()
  const useStdin = argv.includes('--stdin') || argv[0] === '-'
  const raw = useStdin ? await readStdinFull() : runNpmAuditJson(cwd)

  const direct = loadDirectDeps(cwd)
  const pkgToRoot = loadLockfileRootMap(cwd, direct)
  const audit = JSON.parse(raw)
  const vulns = audit.vulnerabilities || {}

  const rows = []
  /** @type {Record<string, Record<string, number>>} */
  const byRoot = {}

  for (const [pkgName, data] of Object.entries(vulns)) {
    const sev = data.severity || 'low'
    const responsible = rootResponsible(data, direct, pkgToRoot, pkgName)

    if (!byRoot[responsible]) {
      byRoot[responsible] = { critical: 0, high: 0, info: 0, low: 0, moderate: 0 }
    }
    byRoot[responsible][sev] = (byRoot[responsible][sev] || 0) + 1

    rows.push({
      responsible,
      severity: sev,
      vulnerablePackage: pkgName,
    })
  }

  rows.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])

  const meta = audit.metadata?.vulnerabilities
  if (meta && meta.total > 0) {
    const bits = ['critical', 'high', 'moderate', 'low', 'info']
      .filter((k) => meta[k])
      .map((k) => `${k}: ${meta[k]}`)
    console.log(`npm audit: ${meta.total} ${bits.length ? `(${bits.join(', ')})` : ''}\n`)
  } else if (rows.length === 0) {
    console.log('No vulnerabilities reported.')
    process.exit(0)
  }

  console.log('By severity → vulnerable package → responsible dep\n')
  printTable(
    ['Severity', 'Vulnerable package', 'Responsible'],
    rows.map((r) => [r.severity, r.vulnerablePackage, r.responsible]),
  )
  console.log('')

  const roots = Object.keys(byRoot).sort((a, b) => a.localeCompare(b))
  const allKeys = ['critical', 'high', 'moderate', 'low', 'info']
  const sevKeys = allKeys.filter((k) => roots.some((name) => byRoot[name][k]))
  const groupedRows = roots.map((name) => {
    const c = byRoot[name]
    const cells = sevKeys.map((k) => String(c[k] || 0))
    const total = allKeys.reduce((n, k) => n + (c[k] || 0), 0)
    return [name, ...cells, String(total)]
  })

  console.log('By responsible dependency (audit entry counts)\n')
  printTable(['Responsible', ...sevKeys, 'Total'], groupedRows)
}

/**
 * @param {string[]} headers
 * @param {string[][]} dataRows
 */
function printTable(headers, dataRows) {
  const widths = colWidths(headers, dataRows)
  const sep = widths.map((w) => '-'.repeat(w + 2))
  const fmt = (/** @type {string[]} */ cells) =>
    '| ' + cells.map((c, i) => String(c).padEnd(widths[i])).join(' | ') + ' |'
  console.log(fmt(headers))
  console.log('|' + sep.join('|') + '|')
  for (const row of dataRows) console.log(fmt(row))
}

/** @returns {Promise<string>} */
function readStdinFull() {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = []
    process.stdin.on('data', (c) => chunks.push(c))
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    process.stdin.on('error', reject)
  })
}

/** @param {string} cwd */
function runNpmAuditJson(cwd) {
  const r = spawnSync('npm', ['audit', '--json'], {
    cwd,
    encoding: 'utf8',
    maxBuffer: 50 * 1024 * 1024,
  })
  if (r.error) throw r.error
  if (r.status !== 0 && r.status !== 1) {
    throw new Error(r.stderr || `npm audit exited with code ${r.status}`)
  }
  return r.stdout || ''
}

main().catch((err) => {
  console.error(err.message || err)
  process.exit(1)
})
