import express from 'express'
import { z } from 'zod'
import * as util from '../util'

const router = express.Router()

<<<<<<< HEAD:packages/server/src/routes/well-known.ts
// Return the server's did
router.get('/did.json', (_req, res) => {
  const keypair = util.getKeypair(res)
  return res.send({ id: keypair.did() })
})

const webfingerReq = z.object({
  resource: z.string(),
})
export type WebfingerReq = z.infer<typeof webfingerReq>

// Retrieve a user's DID by their username
router.get('/webfinger', async (req, res) => {
  const { resource } = util.checkReqBody(req.query, webfingerReq)
  const db = util.getDB(res)
  const host = util.getOwnHost(req)
  const did = await db.getDidForUser(resource, host)
  if (!did) {
    return res.status(404).send('User DID not found')
  }
  // @TODO: sketch out more of a webfinger doc
  return res.status(200).send({ id: did })
=======
router.get('/adx-did', (_req, res) => {
  // Return the server's did
  // TODO check host header
  return res.send(SERVER_DID)
>>>>>>> cab993c (WIP API branch squash):server/src/routes/well-known.ts
})

export default router
