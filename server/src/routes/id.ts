import express from 'express'
import { z } from 'zod'

import { Repo } from '@adxp/common'
import * as authLib from '@adxp/auth'

import * as auth from '../auth.js'
import { SERVER_DID, SERVER_KEYPAIR } from '../server-identity.js'
import * as util from '../util.js'
import { ServerError } from '../error.js'

const router = express.Router()

export const registerReq = z.object({
  did: z.string(),
  username: z.string(),
  createRepo: z.boolean(),
})
export type RegisterReq = z.infer<typeof registerReq>

router.post('/register', async (req, res) => {
  const { username, did, createRepo } = util.checkReqBody(req.body, registerReq)
  if (username.startsWith('did:')) {
    throw new ServerError(
      400,
      'Cannot register a username that starts with `did:`',
    )
  }

  const { db, blockstore } = util.getLocals(res)
  const host = util.getOwnHost(req)
  if (await db.isNameRegistered(username, host)) {
    throw new ServerError(409, 'Username already taken')
  } else if (await db.isDidRegistered(did)) {
    throw new ServerError(409, 'Did already registered')
  }

  const ucanStore = await auth.checkReq(
    req,
    authLib.hasAudience(SERVER_DID),
    authLib.hasMaintenancePermission(did),
  )

  await db.registerDid(username, did, host)
  // create empty repo
  if (createRepo) {
    const authStore = new authLib.AuthStore(SERVER_KEYPAIR, ucanStore)
    const repo = await Repo.create(blockstore, did, authStore)
    await db.createRepoRoot(did, repo.cid)
  }

  return res.sendStatus(200)
})

export default router
