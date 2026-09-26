// Regenerates the vectors and fails if they differ from the checked-in file,
// proving the file is what @orbitdb/core 4.0.0 produces. The
// simple-encryption cases use random salts and nonces, so they are skipped.
import { execFileSync } from 'node:child_process'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isDeepStrictEqual } from 'node:util'

const checkedIn = '../../internal/testutil/testdata/js-vectors.json'
const dir = mkdtempSync(join(tmpdir(), 'jsvectors-'))
try {
  const fresh = join(dir, 'js-vectors.json')
  execFileSync(process.execPath, ['generate.mjs', fresh], { stdio: 'inherit' })
  const strip = (file) => {
    const v = JSON.parse(readFileSync(file, 'utf8'))
    delete v.simpleEncryption
    return v
  }
  if (!isDeepStrictEqual(strip(checkedIn), strip(fresh))) {
    console.error('js-vectors.json is out of date: run `npm run generate` and commit the result')
    process.exit(1)
  }
  console.log('js-vectors.json matches @orbitdb/core')
} finally {
  rmSync(dir, { recursive: true, force: true })
}
