import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

describe('production import and secret guard', () => {
  it('keeps fixture adapters and known fixture secrets out of every production source file', () => {
    const script = path.resolve(import.meta.dirname, '../scripts/guard-production.mjs')
    expect(() => execFileSync(process.execPath, [script], { stdio: 'pipe' })).not.toThrow()
  })
})
