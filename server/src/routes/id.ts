import express from 'express'
import { z } from 'zod'

import { Repo, ucanCheck, check } from '@bluesky-demo/common'

import * as auth from '../auth.js'
import { SERVER_DID, SERVER_KEYPAIR } from '../server-identity.js'
import * as util from '../util.js'
import { ServerError } from '../error.js'

const router = express.Router()

export const registerReq = z.object({
  did: z.string(),
  username: z.string(),
})
export type registerReq = z.infer<typeof registerReq>

router.post('/register', async (req, res) => {
  if (!check.is(req.query, registerReq)) {
    throw new ServerError(400, 'Poorly formatted request')
  }
  const { username, did } = req.body
  if (username.startsWith('did:')) {
    throw new ServerError(
      400,
      'Cannot register a username that starts with `did:`',
    )
  }
  const { db, blockstore } = util.getLocals(res)
  const ucanStore = await auth.checkReq(
    req,
    ucanCheck.hasAudience(SERVER_DID),
    ucanCheck.hasMaintenancePermission(did),
  )
  // create empty repo
  const repo = await Repo.create(blockstore, did, SERVER_KEYPAIR, ucanStore)
  await Promise.all([
    db.registerDid(username, did),
    db.createRepoRoot(did, repo.cid),
  ])
  return res.sendStatus(200)
})

export default router
