// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { ESLint } from 'eslint'
import nativeDialogsTs from '../../lint-fixtures/native-dialogs.ts?raw'
import nativeDialogVue from '../../lint-fixtures/NativeDialog.vue?raw'

/**
 * Lints fixture text as if it were the source file at path (relative to server/web, the working directory of
 * `npm run test`) and returns the lines marked "// forbidden" and the lines with errors.
 */
async function lint(text: string, path: string): Promise<{ forbidden: number[]; reported: number[] }> {
  const [result] = await new ESLint().lintText(text, { filePath: path })
  const forbidden = text.split('\n').flatMap((line, i) => (line.includes('// forbidden') ? [i + 1] : []))
  const reported = result.messages.filter((m) => m.severity === 2).map((m) => m.line)
  return { forbidden, reported }
}

describe('ESLint forbids browser-native dialogs (ADR 0018)', () => {
  it('in TypeScript modules', async () => {
    const { forbidden, reported } = await lint(nativeDialogsTs, 'src/lib/fixture.ts')
    expect(forbidden.length).toBe(9)
    for (const line of forbidden) expect(reported, `line ${line}`).toContain(line)
  })

  it('in single-file components', async () => {
    const { forbidden, reported } = await lint(nativeDialogVue, 'src/components/Fixture.vue')
    expect(forbidden.length).toBe(1)
    for (const line of forbidden) expect(reported, `line ${line}`).toContain(line)
  })
})
