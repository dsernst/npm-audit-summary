#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
/// <reference types="node" />
/**
 * Concise npm audit: flat table (severity → package → responsible) + grouped counts.
 * Reads JSON from stdin, or runs `npm audit --json` in cwd when stdin is a TTY.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

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

/** Common transitives pulled in by firebase-admin; attribute to that root when unambiguous. */
const FIREBASE_TRANSITIVE = new Set([
  '@google-cloud/firestore',
  '@google-cloud/storage',
  'fast-xml-parser',
  'google-gax',
  'protobufjs',
  'teeny-request',
])

/**
 * @typedef {object} AuditVulnEntry
 * @property {string} [name]
 * @property {{ name?: string }} [fixAvailable]
 * @property {string[]} [nodes]
 * @property {string[]} [effects]
 * @property {boolean} [isDirect]
 */

/**
 * @param {AuditVulnEntry} v
 * @param {Set<string>} direct
 * @returns {string}
 */
function rootResponsible(v, direct) {
  if (v.fixAvailable && typeof v.fixAvailable === 'object' && v.fixAvailable.name) {
    return v.fixAvailable.name
  }

  const nodes = v.nodes || []
  const path0 = nodes[0] || ''

  if (path0.includes('node_modules/@google-cloud/') || path0.includes('/@google-cloud/storage/')) {
    return 'firebase-admin'
  }
  if (path0.includes('node_modules/cypress/') || path0.includes('node_modules/@cypress/')) {
    return 'cypress'
  }
  if (path0.includes('node_modules/mailgun-js/')) {
    return 'mailgun-js'
  }
  if (path0.includes('node_modules/patch-package/')) {
    return 'patch-package'
  }

  if (v.name === '@tootallnate/once' && !path0.includes('mailgun')) {
    return 'firebase-admin'
  }

  if (v.name != null && FIREBASE_TRANSITIVE.has(v.name)) {
    return 'firebase-admin'
  }

  const effects = v.effects || []
  const directHit = effects.find((/** @type {string} */ e) => direct.has(e))
  if (directHit) return directHit
  if (effects.length) return effects[effects.length - 1]
  if (v.isDirect) return v.name ?? '(unresolved)'
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
  npm-audit-report              # runs npm audit --json in the current directory
  npm audit --json | npm-audit-report --stdin
  npm audit --json | npm-audit-report -

Requires package.json in the current working directory for the "responsible" column.

Options:
  --stdin, -   Read audit JSON from stdin instead of running npm audit.`)
    process.exit(0)
  }

  const cwd = process.cwd()
  const useStdin = argv.includes('--stdin') || argv[0] === '-'
  const raw = useStdin ? await readStdinFull() : runNpmAuditJson(cwd)

  const direct = loadDirectDeps(cwd)
  const audit = JSON.parse(raw)
  const vulns = audit.vulnerabilities || {}

  const rows = []
  /** @type {Record<string, Record<string, number>>} */
  const byRoot = {}

  for (const [pkgName, data] of Object.entries(vulns)) {
    const sev = data.severity || 'low'
    const responsible = rootResponsible(data, direct)

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
