// A JavaScript OrbitDB peer for go-orbitdb's interop tests.
//
// It runs @orbitdb/core 4.0.0 on Helia over TCP/Noise/Yamux with gossipsub
// and bitswap on 127.0.0.1, and takes one JSON command per line on stdin,
// answering with one JSON line on stdout: {"id": n, "result": ...} or
// {"id": n, "error": "..."}. Logs go to stderr.
import { createInterface } from 'node:readline'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHelia } from 'helia'
import { bitswap } from '@helia/block-brokers'
import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { identify } from '@libp2p/identify'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { gossipsub } from '@libp2p/gossipsub'
import { MemoryBlockstore } from 'blockstore-core'
import { multiaddr } from '@multiformats/multiaddr'
import { createOrbitDB, IPFSAccessController, OrbitDBAccessController, Documents } from '@orbitdb/core'
import SimpleEncryption from '@orbitdb/simple-encryption'

const log = (...args) => console.error('[js-peer]', ...args)

const libp2p = await createLibp2p({
  addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
  transports: [tcp()],
  connectionEncrypters: [noise()],
  streamMuxers: [yamux()],
  services: {
    identify: identify(),
    pubsub: gossipsub({ allowPublishToZeroTopicPeers: true })
  }
})
const ipfs = await createHelia({ libp2p, blockstore: new MemoryBlockstore(), blockBrokers: [bitswap()], routers: [] })
const directory = mkdtempSync(join(tmpdir(), 'orbitdb-js-peer-'))
const orbitdb = await createOrbitDB({ ipfs, id: 'js-peer', directory })

const dbs = new Map()
const errors = []

const toJSON = (v) => JSON.parse(JSON.stringify(v, (k, x) => x instanceof Uint8Array ? { bytes: Buffer.from(x).toString('hex') } : x))

const accessController = ({ access, write }) => {
  if (access === 'orbitdb') return OrbitDBAccessController({ write })
  return IPFSAccessController({ write })
}

const commands = {
  info: async () => ({
    peerId: libp2p.peerId.toString(),
    addrs: libp2p.getMultiaddrs().map(String),
    identity: { id: orbitdb.identity.id, hash: orbitdb.identity.hash, publicKey: orbitdb.identity.publicKey }
  }),
  dial: async ({ addr }) => {
    await libp2p.dial(multiaddr(addr))
    return true
  },
  open: async ({ address, type, write, access, indexBy, password }) => {
    const options = { type }
    if (write || access) options.AccessController = accessController({ access, write })
    if (indexBy) options.Database = Documents({ indexBy })
    if (password !== undefined) {
      options.encryption = {
        data: await SimpleEncryption({ password }),
        replication: await SimpleEncryption({ password })
      }
    }
    const db = await orbitdb.open(address, options)
    db.events.on('error', (e) => { errors.push(String(e)); log('db error', e) })
    dbs.set(db.address, db)
    return { address: db.address, type: db.type, name: db.name }
  },
  put: async ({ address, key, value }) => dbs.get(address).put(key, value),
  del: async ({ address, key }) => dbs.get(address).del(key),
  add: async ({ address, value }) => dbs.get(address).add(value),
  putDoc: async ({ address, doc }) => dbs.get(address).put(doc),
  get: async ({ address, key }) => toJSON(await dbs.get(address).get(key) ?? null),
  all: async ({ address }) => toJSON(await dbs.get(address).all()),
  values: async ({ address }) => (await dbs.get(address).log.values()).map(e => ({ hash: e.hash, payload: toJSON(e.payload) })),
  heads: async ({ address }) => (await dbs.get(address).log.heads()).map(e => e.hash),
  peers: async ({ address }) => [...dbs.get(address).peers],
  grant: async ({ address, capability, id }) => {
    await dbs.get(address).access.grant(capability, id)
    return true
  },
  waitAll: async ({ address, count, timeout }) => {
    const deadline = Date.now() + (timeout ?? 30000)
    while (Date.now() < deadline) {
      const all = await dbs.get(address).all()
      if (all.length >= count) return toJSON(all)
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    throw new Error(`timed out waiting for ${count} records in ${address}`)
  },
  errors: async () => errors,
  close: async ({ address }) => {
    await dbs.get(address).close()
    dbs.delete(address)
    return true
  }
}

const reply = (msg) => process.stdout.write(JSON.stringify(msg) + '\n')

const shutdown = async () => {
  try {
    await orbitdb.stop()
    await ipfs.stop()
  } finally {
    rmSync(directory, { recursive: true, force: true })
    process.exit(0)
  }
}

const rl = createInterface({ input: process.stdin })
rl.on('line', async (line) => {
  let msg
  try {
    msg = JSON.parse(line)
  } catch (e) {
    return reply({ id: -1, error: `bad request: ${e.message}` })
  }
  if (msg.cmd === 'stop') {
    reply({ id: msg.id, result: true })
    return shutdown()
  }
  try {
    const fn = commands[msg.cmd]
    if (!fn) throw new Error(`unknown command ${msg.cmd}`)
    reply({ id: msg.id, result: (await fn(msg.args ?? {})) ?? null })
  } catch (e) {
    reply({ id: msg.id, error: e.message ?? String(e) })
  }
})
rl.on('close', shutdown)

reply({ id: 0, result: 'ready' })
