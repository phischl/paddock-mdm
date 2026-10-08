import { describe, expect, it } from 'vitest'
import { licenseAllowed, licenseProblems } from '../lib/licenseCheck'

const allowed = new Set(['MIT', 'Apache-2.0', 'BSD-3-Clause'])

describe('licenseAllowed', () => {
  it.each([
    ['MIT', true],
    ['(MIT OR GPL-3.0)', true],
    ['(MIT AND Apache-2.0)', true],
    ['(MIT OR (GPL-3.0 AND Apache-2.0))', true],
    ['(MIT AND GPL-3.0)', false],
    ['GPL-3.0 AND MIT', false],
    ['GPL-3.0', false],
    ['SEE LICENSE IN LICENSE-MIT', false],
    ['UNKNOWN', false],
    ['MIT*', false],
    ['Apache-2.0 WITH LLVM-exception', false],
    ['(MIT', false],
    ['MIT OR', false],
    ['', false],
  ])('%s → %s', (expr, want) => {
    expect(licenseAllowed(expr, allowed)).toBe(want)
  })
})

describe('licenseProblems', () => {
  it('names every package outside the allow list, including one without a license', () => {
    const problems = licenseProblems(
      {
        'ok@1.0.0': { licenses: 'MIT' },
        'dual@1.0.0': { licenses: '(MIT OR GPL-3.0)' },
        'both@1.0.0': { licenses: '(MIT AND GPL-3.0)' },
        'see@1.0.0': { licenses: 'SEE LICENSE IN LICENSE.md' },
        'none@1.0.0': {},
        'list@1.0.0': { licenses: ['MIT', 'GPL-3.0'] },
      },
      ['MIT'],
    )
    expect(problems).toEqual([
      'both@1.0.0: "(MIT AND GPL-3.0)"',
      'list@1.0.0: ["MIT","GPL-3.0"]',
      'none@1.0.0: no license',
      'see@1.0.0: "SEE LICENSE IN LICENSE.md"',
    ])
  })
})
