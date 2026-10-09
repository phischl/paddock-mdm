// License gate of the npm production dependencies (plan M6b decision 3): reads `license-checker-rseidelsohn --json`
// from the file in argv[2] and checks every package against the allow list in argv[3] (separated by ";"). Run by
// `make lint-licenses`.
import { readFileSync } from 'node:fs'
import { licenseProblems, type LicenseEntry } from '../src/lib/licenseCheck.ts'

const [file, allowList] = process.argv.slice(2)
if (!file || !allowList) {
  console.error('usage: check-licenses.ts <license-checker.json> <allowed;licenses>')
  process.exit(2)
}
const packages = JSON.parse(readFileSync(file, 'utf8')) as Record<string, LicenseEntry>
const problems = licenseProblems(packages, allowList.split(';'))
if (problems.length > 0) {
  console.error('npm packages with a license outside the allow list:\n  ' + problems.join('\n  '))
  process.exit(1)
}
console.log(`npm licenses: ${Object.keys(packages).length} production packages allowed`)
