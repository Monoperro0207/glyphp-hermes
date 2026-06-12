// Demo Glyph server for glyphp-hermes: an in-memory notes provider.
//
//   npm install && npm run server          → normal corpus
//   npm run server:tamper                  → notes.add re-issued as riskTier
//                                            'danger' (demonstrates the
//                                            changed-card gate across restarts)
//
// Glyphs:
//   notes.list    safe                       (TOFU auto-pins)
//   notes.add     caution, side effects      (TOFU auto-pins with max caution)
//   notes.delete  danger + requiresConfirmation (blocked until /glyph trust,
//                                            then gated per-call)
//   notes.export  danger + container-digest attestation (passes an
//                                            attestation.require=danger policy)
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { computeGlyphId, generateKeyPair } from '@glyphp/core'
import { GlyphServer, defineGlyph } from '@glyphp/server'
import { z } from 'zod'

const TAMPER = process.argv.includes('--tamper')
const PORT = Number(process.env.GLYPH_DEMO_PORT || 3100)

// Persist the server identity across restarts: a key swap is itself a
// breaking card change, and the --tamper demo should show ONLY the riskTier
// change. Demo-only convenience — production servers manage keys properly.
const KEY_FILE = new URL('.demo-keypair.json', import.meta.url)
let keyPair
if (existsSync(KEY_FILE)) {
  keyPair = JSON.parse(readFileSync(KEY_FILE, 'utf-8'))
} else {
  keyPair = generateKeyPair()
  writeFileSync(KEY_FILE, JSON.stringify(keyPair))
}

const notes = new Map()
let nextId = 1

const list = defineGlyph({
  name: 'notes.list',
  intent: 'List all stored notes',
  tags: ['notes', 'read'],
  cost: {
    latency: 'fast',
    sideEffects: false,
    reversible: true,
    riskTier: 'safe',
    requiresConfirmation: false,
  },
  idempotent: true,
  input: z.object({}),
  output: z.object({
    notes: z.array(z.object({ id: z.number(), text: z.string() })),
  }),
  examples: [{ description: 'empty', input: {}, output: { notes: [] } }],
  failureModes: [],
  provider: 'glyphp-hermes-demo',
  handler: async () => ({
    notes: [...notes.entries()].map(([id, text]) => ({ id, text })),
  }),
})

const add = defineGlyph({
  name: 'notes.add',
  intent: 'Append a note to the store',
  tags: ['notes', 'write'],
  cost: {
    latency: 'fast',
    sideEffects: true,
    reversible: true,
    // --tamper simulates a re-deploy that widened the blast radius: the card
    // id changes, and a pinning client must park the tool for re-approval.
    riskTier: TAMPER ? 'danger' : 'caution',
    requiresConfirmation: false,
  },
  idempotent: false,
  input: z.object({ text: z.string().min(1).describe('Note text') }),
  output: z.object({ id: z.number() }),
  examples: [{ description: 'add', input: { text: 'hi' }, output: { id: 1 } }],
  failureModes: [{ code: 'EMPTY', description: 'text must not be empty' }],
  provider: 'glyphp-hermes-demo',
  handler: async ({ text }) => {
    const id = nextId++
    notes.set(id, text)
    return { id }
  },
})

const del = defineGlyph({
  name: 'notes.delete',
  intent: 'Permanently delete a note by id',
  tags: ['notes', 'write', 'destructive'],
  cost: {
    latency: 'fast',
    sideEffects: true,
    reversible: false,
    riskTier: 'danger',
    requiresConfirmation: true,
  },
  idempotent: false,
  input: z.object({ id: z.number().int().describe('Note id to delete') }),
  output: z.object({ deleted: z.boolean() }),
  examples: [{ description: 'delete', input: { id: 1 }, output: { deleted: true } }],
  failureModes: [{ code: 'NOT_FOUND', description: 'no note with that id' }],
  provider: 'glyphp-hermes-demo',
  handler: async ({ id }) => ({ deleted: notes.delete(id) }),
})

// notes.export carries a container-digest attestation. The attestation enters
// the card's canonical content, so the id must be recomputed after attaching.
const exportDef = defineGlyph({
  name: 'notes.export',
  intent: 'Export every note as a JSON document',
  tags: ['notes', 'read', 'export'],
  cost: {
    latency: 'medium',
    sideEffects: true,
    reversible: true,
    riskTier: 'danger',
    requiresConfirmation: false,
  },
  idempotent: true,
  input: z.object({}),
  output: z.object({ document: z.string() }),
  examples: [],
  failureModes: [],
  provider: 'glyphp-hermes-demo',
  handler: async () => ({
    document: JSON.stringify([...notes.entries()].map(([id, text]) => ({ id, text }))),
  }),
})
exportDef.card.attestation = {
  type: 'container-digest',
  payload: JSON.stringify({ digest: `sha256:${'ab'.repeat(32)}` }),
}
exportDef.card.id = computeGlyphId(exportDef.card)

const server = new GlyphServer({ port: PORT, keyPair })
server.register(list)
server.register(add)
server.register(del)
server.register(exportDef)
await server.start()

console.log(`glyphp-hermes demo server on http://127.0.0.1:${PORT}${TAMPER ? ' (TAMPERED notes.add → danger)' : ''}`)
console.log('glyphs: notes.list (safe) · notes.add (caution) · notes.delete (danger+confirm) · notes.export (danger+attested)')
