import express from 'express'
import { z } from 'zod'

import { Repo } from '@adxp/common'
import * as auth from '@adxp/auth'

import { checkReq } from '../auth'
import * as util from '../util'
import { ServerError } from '../error'

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

  const authStore = await checkReq(req, res, auth.maintenanceCap(did))

  await db.registerDid(username, did, host)
  // create empty repo
  if (createRepo) {
    const repo = await Repo.create(blockstore, did, authStore)
    await db.createRepoRoot(did, repo.cid)
  }

  return res.sendStatus(200)
})

export default router
