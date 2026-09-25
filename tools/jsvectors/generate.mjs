// Generates the golden vectors go-orbitdb's tests compare against.
//
// Every scenario runs on @orbitdb/core 4.0.0 with the keys of its own test
// fixture keystore. Signatures are deterministic (RFC 6979), so the Go
// implementation replaying a scenario with the same keys must produce
// exactly the same identities, entry bytes, hashes and orderings.
//
// Usage: npm install && npm run generate
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { Log, Entry, Identities, KeyStore, MemoryStorage, IPFSAccessController } from '@orbitdb/core'
import ManifestStore from '@orbitdb/core/src/manifest-store.js'
import OrbitDBAddress, { isValidAddress } from '@orbitdb/core/src/address.js'
import pathJoin from '@orbitdb/core/src/utils/path-join.js'
import { privateKeyFromRaw } from '@libp2p/crypto/keys'
import SimpleEncryption from '@orbitdb/simple-encryption'

const out = process.argv[2] || 'js-vectors.json'
const hex = (bytes) => Buffer.from(bytes).toString('hex')
const unhex = (s) => Uint8Array.from(Buffer.from(s, 'hex'))

// The raw private keys of test/fixtures/newtestkeys2, by keystore id.
const keys = {
  '020863639c1793cdc32abffca1c903f96d282de5530ab3167d661caf96b827369c': '8b0d3e5ee88edea5314eca1ae8d4f9e276bdc08ac163ba540dc312014b568e37',
  '023d1ef7a14d2d4c901afb3a244875c988f4e69ccd3df1575ae08097a314ccf8c0': 'fa9b7df085feccaff5a83f74cb46381c623dc6dc652e598277a22d7659c37066',
  '02c322b7edb44fe8e0f4d8d70feb8a9c30b30721110a355ec9f200b4e49a4637d4': '0b43ca53b8875baf229faed396f0efdd21498984210bb3f4df04364299ee430b',
  '02e7247a4c155b63d182a23c70cb6fe8ba2e44bc9e9d62dc45d4c4167ccde95944': '5c557f3ca56651e22e68ee770da8e7cc6f12d30081f60a3ca4b5f9f3a9a5f9df',
  '031e1ec273bc1badb26164a4394b20e587c484ad9409ae20d0545a0976ec7d44b6': 'c6a97e6b53e0f966e97cd91c58344ca1745c2a6dd64790eb0ee3adb3cd11d4d3',
  '03602a3da3eb35f1148e8028f141ec415ef7f6d4103443edbfec2a0711d716f53f': '1b57d51eec137085753bd911bd874024cd5d91edd8802809023666675635290b',
  '03c2c4887bb3fbc131f6874959a0fbe646d43a200cf81056e22f9405c1f58ba611': '4ba52f65ada1d2ca5f70c562202c1a9d9cbef125df78525b0737aff3d13653f4',
  '03eea986152805dcfe9292be7aa3560949e1db0f0972be4290824c11c661f419de': 'b235eede06363471087291ddefeb31ce74209d43c29c87475d0ebb5397fd2c90',
  '0x01234567890abcdefghijklmnopqrstuvwxyz': '9c5d99a925257730d70ae64af9169d8f7e3aac27a211416698a00bfe8cd2e4bd',
  QmFoo: 'efa068bfa5bd6d63ddbef943c55618f163f204b824be8a135de6c660a2a73d34',
  key1: 'be88e7bb43ae78fa596966bf24d97ddfd0d17b88a1aafb9f22dd8b1d8c525d7f',
  pubKey: '2dff73c70964e8cb9c7bcb1edfdd8ce327ef55ebdad92b2d2656a10f8583c57b',
  userA: '5f74f154ac4591ccf8a67f7edc98971759d684c07f53037ea0d361e2ba3f4683',
  userB: '7824c1579131baa6d6c34736b95c596c6c81afdb2f84654228eb2c75403e4c65',
  userC: '81f78e97259ce190f46141cb5a3d9a9c006557126e8bb752bc78d62d07c1bb3e',
  userX: 'dfe24b20dbcb02217cf0a487f1db3004397160091ba6539dfb8042e94568f47e'
}

const keystore = await KeyStore({ storage: await MemoryStorage() })
for (const [id, raw] of Object.entries(keys)) {
  // Sanity check: the fixture keys are secp256k1.
  if (privateKeyFromRaw(unhex(raw)).type !== 'secp256k1') throw new Error(`${id} is not secp256k1`)
  await keystore.addKey(id, { privateKey: unhex(raw) })
}
const identities = await Identities({ keystore })

const vectors = { generator: '@orbitdb/core@4.0.0', identities: {}, entries: [], logs: {}, iterators: {}, manifests: [], addresses: [], encryption: {} }

// Identities.
const identity = {}
for (const id of ['userA', 'userB', 'userC', 'userX']) {
  const i = await identities.createIdentity({ id })
  identity[id] = i
  vectors.identities[id] = { id: i.id, publicKey: i.publicKey, signatures: i.signatures, type: i.type, hash: i.hash, bytes: hex(i.bytes) }
}

// Single entries with every kind of payload. The Go test builds the same
// payloads from Go values (by name) and must get the same hash.
const payloads = {
  string: 'hello',
  string2: 'hello world',
  unicode: 'héllo 世界 🌍',
  int: 42,
  negative: -7,
  zero: 0,
  maxSafeInteger: Number.MAX_SAFE_INTEGER,
  float: 3.25,
  bool: true,
  bytes: new Uint8Array([1, 2, 3]),
  list: [1, 'two', null, [3]],
  map: { op: 'PUT', key: 'k', value: { nested: [1, 2.5, 'x'], flag: false, nothing: null } },
  eventsAdd: { op: 'ADD', key: null, value: 'x' },
  documentPut: { op: 'PUT', key: 'doc1', value: { _id: 'doc1', title: 'hi', views: 10 } }
}
for (const [name, payload] of Object.entries(payloads)) {
  const e = await Entry.create(identity.userA, 'A', payload)
  const { hash, bytes } = await Entry.encode(e)
  vectors.entries.push({ name, logId: 'A', writer: 'userA', hash, bytes: hex(bytes) })
}
{
  // An entry with an explicit clock, next and refs.
  const first = await Entry.create(identity.userA, 'A', 'hello')
  const { hash: firstHash } = await Entry.encode(first)
  const e = await Entry.create(identity.userB, 'A', 'second', null, { id: identity.userB.publicKey, time: 7 }, [firstHash], [firstHash])
  const { hash, bytes } = await Entry.encode(e)
  vectors.entries.push({ name: 'withClockNextRefs', logId: 'A', writer: 'userB', clockTime: 7, next: [firstHash], refs: [firstHash], payload: 'second', hash, bytes: hex(bytes) })
}

// Log scenarios. ops are replayed verbatim by the Go test:
//   ["append", log, payload, referencesCount]
//   ["join", into, from]
//   ["joinEntry", into, from, index]  (index into from's values)
const scenarios = {
  singleWriter: { logId: 'A', writers: { a: 'userA' }, ops: Array.from({ length: 20 }, (_, i) => ['append', 'a', `entry${i}`, 16]) },
  refs0: { logId: 'R', writers: { a: 'userA' }, ops: Array.from({ length: 10 }, (_, i) => ['append', 'a', `e${i}`, 0]) },
  refs1: { logId: 'R', writers: { a: 'userA' }, ops: Array.from({ length: 10 }, (_, i) => ['append', 'a', `e${i}`, 1]) },
  refs2: { logId: 'R', writers: { a: 'userA' }, ops: Array.from({ length: 10 }, (_, i) => ['append', 'a', `e${i}`, 2]) },
  refs4: { logId: 'R', writers: { a: 'userA' }, ops: Array.from({ length: 10 }, (_, i) => ['append', 'a', `e${i}`, 4]) },
  refs64: { logId: 'R', writers: { a: 'userA' }, ops: Array.from({ length: 70 }, (_, i) => ['append', 'a', `e${i}`, 64]) },
  twoWriters: {
    logId: 'X',
    writers: { a: 'userA', b: 'userB' },
    ops: [
      ['append', 'a', 'a1', 16], ['append', 'b', 'b1', 16],
      ['join', 'a', 'b'],
      ['append', 'a', 'a2', 16], ['append', 'b', 'b2', 16], ['append', 'b', 'b3', 16],
      ['join', 'b', 'a'],
      ['append', 'b', 'b4', 16], ['append', 'a', 'a3', 16],
      ['join', 'a', 'b'], ['join', 'b', 'a'],
      ['append', 'a', 'a4', 16]
    ]
  },
  threeWriters: {
    logId: 'X',
    writers: { a: 'userA', b: 'userB', c: 'userC', x: 'userX' },
    ops: [
      ...Array.from({ length: 5 }, (_, i) => [['append', 'a', `A${i}`, 4], ['append', 'b', `B${i}`, 4], ['append', 'c', `C${i}`, 4]]).flat(),
      ['join', 'a', 'b'], ['append', 'a', 'A5', 4],
      ['join', 'c', 'a'], ['append', 'c', 'C5', 4], ['append', 'c', 'C6', 4],
      ['join', 'x', 'c'], ['append', 'x', 'X0', 4],
      ['join', 'b', 'x'], ['append', 'b', 'B5', 4],
      ['joinEntry', 'a', 'b', -1],
      ['join', 'c', 'b'], ['join', 'x', 'a'], ['join', 'a', 'c'],
      ['append', 'a', 'A6', 4], ['append', 'x', 'X1', 4]
    ]
  },
  sameIdentityConcurrent: {
    // Two logs of the same writer append at the same clock times, so
    // entries tie on (time, id) and ordering falls back to stability.
    logId: 'S',
    writers: { a: 'userA', b: 'userA' },
    ops: [
      ['append', 'a', 'one', 16], ['append', 'b', 'uno', 16],
      ['append', 'a', 'two', 16], ['append', 'b', 'dos', 16],
      ['join', 'a', 'b'], ['join', 'b', 'a'],
      ['append', 'a', 'three', 16], ['append', 'b', 'tres', 16],
      ['join', 'a', 'b'], ['join', 'b', 'a']
    ]
  },
  deepPayloads: {
    logId: 'P',
    writers: { a: 'userA' },
    ops: [
      ['append', 'a', { op: 'PUT', key: 'k1', value: 'v1' }, 16],
      ['append', 'a', { op: 'PUT', key: 'k2', value: { n: 1, f: 1.5, l: [true, null] } }, 16],
      ['append', 'a', { op: 'DEL', key: 'k1', value: null }, 16],
      ['append', 'a', { op: 'ADD', key: null, value: 12345678901 }, 16]
    ]
  }
}

const describeLog = async (log) => {
  const values = await log.values()
  const heads = await log.heads()
  const clock = await log.clock()
  return {
    values: values.map(e => ({ hash: e.hash, payload: e.payload, next: e.next, refs: e.refs, clock: e.clock })),
    heads: heads.map(e => e.hash),
    clock
  }
}

for (const [name, sc] of Object.entries(scenarios)) {
  const logs = {}
  for (const [key, writer] of Object.entries(sc.writers)) {
    logs[key] = await Log(identity[writer], { logId: sc.logId })
  }
  const results = []
  for (const op of sc.ops) {
    if (op[0] === 'append') {
      const e = await logs[op[1]].append(op[2], { referencesCount: op[3] })
      results.push(e.hash)
    } else if (op[0] === 'join') {
      await logs[op[1]].join(logs[op[2]])
      results.push(null)
    } else if (op[0] === 'joinEntry') {
      const values = await logs[op[2]].values()
      const e = values.at(op[3])
      await logs[op[1]].storage.merge(logs[op[2]].storage)
      const updated = await logs[op[1]].joinEntry(e)
      results.push(updated)
    }
  }
  const final = {}
  for (const key of Object.keys(sc.writers)) {
    final[key] = await describeLog(logs[key])
  }
  vectors.logs[name] = { ...sc, results, final }
}

// Iterators over a 100-entry log, as in test/oplog/iterator.test.js.
{
  const log = await Log(identity.userC, { logId: 'X' })
  const hashes = []
  for (let i = 0; i < 100; i++) {
    hashes.push((await log.append('entry' + i)).hash)
  }
  const at = (i) => hashes[i]
  const cases = [
    { lte: 67, amount: 10 }, { lt: 67, amount: 10 }, { gt: 67, amount: 5 }, { gte: 67, amount: 12 },
    { lt: 67, gt: 56 }, { lt: 67, gte: 42 }, { lte: 67, gt: 63 }, { lte: 67, gte: 58 },
    {}, { gte: 0, lte: 99, amount: 1000 },
    { gt: 67 }, { gte: 67 }, { lt: 67 }, { lte: 67 },
    { gt: 3, amount: 1000 }, { gte: 3, amount: 1000 },
    { amount: 1 }, { amount: 7 }, { lte: 0 }, { lt: 0 }, { gt: 99 }, { gte: 99, amount: 3 }
  ]
  const results = []
  for (const c of cases) {
    const opts = {}
    for (const k of ['gt', 'gte', 'lt', 'lte']) if (c[k] !== undefined) opts[k] = at(c[k])
    if (c.amount !== undefined) opts.amount = c.amount
    const got = []
    for await (const e of log.iterator(opts)) got.push(e.payload)
    results.push({ options: c, payloads: got })
  }
  vectors.iterators = { logId: 'X', writer: 'userC', size: 100, hashes, cases: results }
}

// Access controller and manifest blocks, and database addresses.
{
  const acStorage = await MemoryStorage()
  const orbitdbStub = { identity: identity.userA }
  for (const write of [[identity.userA.id], ['*'], [identity.userA.id, identity.userB.id]]) {
    const ac = await IPFSAccessController({ write, storage: acStorage })({ orbitdb: orbitdbStub, identities })
    const manifestStorage = await MemoryStorage()
    const manifestStore = await ManifestStore({ storage: manifestStorage })
    for (const [name, type, meta] of [['mydb', 'keyvalue', undefined], ['events-db', 'events', undefined], ['docs', 'documents', { indexBy: '_id', n: 1 }]]) {
      const { hash, manifest } = await manifestStore.create({ name, type, accessController: ac.address, meta })
      const acHash = ac.address.replace('/ipfs/', '')
      const address = OrbitDBAddress(hash).toString()
      vectors.manifests.push({
        write,
        accessController: ac.address,
        accessControllerBytes: hex(await acStorage.get(acHash)),
        name,
        type,
        meta: meta ?? null,
        hash,
        bytes: hex(await manifestStorage.get(hash)),
        manifest,
        address,
        headsProtocol: pathJoin('/orbitdb/heads/', address)
      })
    }
  }
  for (const a of ['/orbitdb/zdpuAuK3BHpS7NvMBivynypqciYCuy2UW77XYBPUYRnLjnw13', '/orbitdb/zdpuAuK3BHpS7NvMBivynypqciYCuy2UW77XYBPUYRnLjnw13/', '\\orbitdb\\zdpuAuK3BHpS7NvMBivynypqciYCuy2UW77XYBPUYRnLjnw13', 'zdpuAuK3BHpS7NvMBivynypqciYCuy2UW77XYBPUYRnLjnw13', '/orbitdb/Qmdgwt7w4uBsw8LXduzCAuAZmAtNDxyuMYKbc8uwFDdFFZ', '/orbitdb/notacid', '/orbitdb/', 'orbitdb']) {
    vectors.addresses.push({ address: a, valid: isValidAddress(a), string: isValidAddress(a) ? OrbitDBAddress(a).toString() : null })
  }
}

// Encryption hooks with a deterministic toy cipher (XOR with 0x5a, then a
// 4-byte tag) so the hook placement can be compared byte for byte.
{
  const toy = {
    encrypt: async (bytes) => Uint8Array.from([0xde, 0xad, 0xbe, 0xef, ...bytes.map(b => b ^ 0x5a)]),
    decrypt: async (bytes) => Uint8Array.from(bytes.slice(4).map(b => b ^ 0x5a))
  }
  for (const [name, encryption] of Object.entries({ data: { data: toy }, replication: { replication: toy }, both: { data: toy, replication: toy } })) {
    const log = await Log(identity.userA, { logId: 'E', encryption })
    const appended = []
    for (const payload of ['secret', { op: 'PUT', key: 'k', value: 1 }, 'last']) {
      const e = await log.append(payload, { referencesCount: 16 })
      appended.push({ hash: e.hash, bytes: hex(await log.storage.get(e.hash)) })
    }
    const values = await log.values()
    vectors.encryption[name] = { logId: 'E', writer: 'userA', appended, payloads: values.map(e => e.payload) }
  }
}

// @orbitdb/simple-encryption ciphertexts (random salt and nonce, so Go can
// only check that it decrypts them).
{
  vectors.simpleEncryption = []
  for (const password of ['orbitdb', '']) {
    const enc = await SimpleEncryption({ password })
    for (const plaintext of ['hello', '', 'a longer plaintext with some unicode: 世界']) {
      const data = new TextEncoder().encode(plaintext)
      vectors.simpleEncryption.push({ password, plaintext: hex(data), ciphertext: hex(await enc.encrypt(data)) })
    }
  }
}

mkdirSync(dirname(out), { recursive: true })
writeFileSync(out, JSON.stringify(vectors, null, 1) + '\n')
console.log(`wrote ${out}`)
