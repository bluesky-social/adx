import express from 'express'
import { TID } from '@adxp/common'
import { updateTick } from './document'
import { sign } from './signature'
import * as crypto from '@adxp/crypto'
import { z } from 'zod'

// Note: do not use the dev/test key in production
//       pull the prod key from the secret store
export const CONSORTIUM_KEYPAIR = crypto.EcdsaKeypair.import(
  {
    // did:key:zDnaeeL44gSLMViH9khhTbngNd9r72MhUPo4WKPeSfB8xiDTh
    key_ops: [ 'sign' ],
    ext: true,
    kty: 'EC',
    x: 'zn_OWx4zJM5zy8E_WUAJH9OS75K5t6q74D7lMf7AmnQ',
    y: 'trzc_f9i_nOuYRCLMyXxBcpc3OVlylmxdESQ0zdKHeQ',
    crv: 'P-256',
    d: 'Ii__doqqQ5YYZLfKh-LSh1Vm6AqCWHGMrBTDYKaEWfU',
  },
  {
    exportable: true,
  },
)

let consortiumCrypto = async () => {
    let key = (await CONSORTIUM_KEYPAIR)
    return {
    did: (): string => { return key.did() },
    sign: async (msg:Uint8Array): Promise<Uint8Array> => {
      return await key.sign(msg)
    },
    verifyDidSig: crypto.verifyDidSig,
  }
}
// const literalSchema = z.union([z.string(), z.number(), z.boolean(), z.null()])
// type Literal = z.infer<typeof literalSchema>
// type Json = Literal | { [key: string]: Json } | Json[]
// const jsonSchema: z.ZodType<Json> = z.lazy(() =>
//   z.union([literalSchema, z.array(jsonSchema), z.record(jsonSchema)]),
// )

// const Patch = z.tuple([
//   z.literal('put').or(z.literal('del')),
//   z.string().array(),
//   jsonSchema,
// ])
// type Patch = z.infer<typeof Patch>

// const Diff = z.object({
//   prev: z.string().regex(/[2-7a-z]{4}-[2-7a-z]{3}-[2-7a-z]{4}-[2-7a-z]{2}/),
//   patches: Patch.array(),
//   // base58btc alphabet 123456789 ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz
//   key: z.string().regex(/did:key:z[1-9A-HJ-NP-Za-km-z]+/),
//   sig: z.string().regex(/z[1-9A-HJ-NP-Za-km-z]+/),
// })
// type Diff = z.infer<typeof Diff>

const router = express.Router()
router.use('/favicon.ico', express.static('static'))
// router.use('/tid', tid)
router.all('/tid', async (req, res) => {
  res.send(
    await sign(
      {
        tid: TID.next().formatted(),
        key: (await consortiumCrypto()).did(),
        sig: '',
      },
      await consortiumCrypto(),
    ),
  )
})

router.get(
  '/:pid([234567abcdefghijklmnopqrstuvwxyz]{16})/',
  async function (req, res) {
    // AIC git
    //
    // Retreve the latest tick from the databace
    // pass the tick and curent tid to the aic lib for signing
    const did = 'did:aic:' + req.params.pid
    const row = await res.locals.db.tickForDid(did) // retreve latest tick
    const prev_tick = row ? JSON.parse(row.tick) : null
    const signedDoc = await updateTick(
      did,
      TID.next().formatted(),
      null, // candidateDiff: this is a get no updates
      prev_tick,
      await consortiumCrypto(),
    )
    res.type('json').send(signedDoc)
  },
)

router.post(
  '/:pid([234567abcdefghijklmnopqrstuvwxyz]{16})/',
  async function (req, res) {
    // extract from post
    const did = 'did:aic:' + req.params.pid
    const candidateDiff = req.body

    // extract from DB
    const row = await res.locals.db.tickForDid(did)
    const prevTid = row ? row.tid : null
    const prev_tick = row ? JSON.parse(row.tick) : null

    // aic lib will do the doc update
    const newTick = await updateTick(
      did, // did from the URL
      TID.next().formatted(), // curent time (tid)
      candidateDiff, // diff that was posted/put
      prev_tick, // tick from db for did:aic
      await consortiumCrypto(), // server's aic key
    )

    if ('error' in newTick) {
      // error return from updateTick
      // type ErrorMessage = { error: string; cause?: ErrorMessage; [index: string]: Value }
      // if there is an error property it is an error don't store in DB
      // also send the last tick that is still valid
      res.status(200)
      res.type('json').send({
        tid: TID.next().formatted(),
        did: `did:aic:${req.params.pid}`,
        tick: prev_tick,
        error: 'error return from updateTick',
        cause: newTick,
      })
      return
    }

    // if the output of updateTick is not an error put in db
    console.log(`Saving ${newTick.did} to AIC at ${newTick.tid}`)
    await res.locals.db.putTickForDid(
      newTick.did,
      newTick.tid,
      prevTid, // gard: if the prevTid has changed the tick from the db is stale
      JSON.stringify(newTick),
    )

    // we reload the tick from the databace if the put failed/pending we return the last tick 
    const storedTick = (await res.locals.db.tickForDid(did)).tick
    res.status(200)
    res.type('json').send(storedTick)
  },
)

export default router
