import { readdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'

const root = path.resolve(import.meta.dirname, '..')
const forbidden = [
  'fixtureTrafficSource',
  'fixture-traffic-source',
  '/fixtures/',
  'Bearer fixture-token',
  'session=fixture-session',
]

async function filesBelow(directory) {
  const entries = await readdir(directory)
  const files = []
  for (const entry of entries) {
    const target = path.join(directory, entry)
    if ((await stat(target)).isDirectory()) files.push(...(await filesBelow(target)))
    else files.push(target)
  }
  return files
}

async function assertClean(directory, label) {
  const files = await filesBelow(directory)
  const violations = []
  for (const file of files) {
    const content = await readFile(file, 'utf8').catch(() => '')
    for (const marker of forbidden) {
      if (content.includes(marker)) violations.push(`${path.relative(root, file)} contains ${marker}`)
    }
  }
  if (violations.length) {
    throw new Error(`${label} fixture guard failed:\n${violations.join('\n')}`)
  }
}

await assertClean(path.join(root, 'src'), 'production source')
if (process.argv.includes('--dist')) await assertClean(path.join(root, 'dist'), 'production bundle')
