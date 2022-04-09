import express from 'express'
import { z } from 'zod'

import { ucanCheck } from '@bluesky-demo/common'
import * as auth from '../../auth.js'
import { ServerError } from '../../error.js'
import * as util from '../../util.js'
import { SERVER_DID } from '../../server-identity.js'

const router = express.Router()

// CREATE

export const createRelReq = z.object({
  creator: z.string(),
  target: z.string(),
  username: z.string(),
})
export type CreateRelReq = z.infer<typeof createRelReq>

router.post('/', async (req, res) => {
  const { creator, target } = util.checkReqBody(req.body, createRelReq)
  const ucanStore = await auth.checkReq(
    req,
    ucanCheck.hasAudience(SERVER_DID),
    ucanCheck.hasRelationshipsPermission(creator),
  )
  const db = util.getDB(res)
  const targetName = await db.getUsername(target)
  if (targetName === null) {
    // @TODO try to find user on network
    throw new ServerError(404, `Could not find user: ${target}`)
  }
  const repo = await util.loadRepo(res, creator, ucanStore)
  await repo.relationships.follow(target, targetName)
  await db.createFollow(creator, target)
  await db.updateRepoRoot(creator, repo.cid)
  res.status(200).send()
})

// DELETE

export const deleteRelReq = z.object({
  creator: z.string(),
  target: z.string(),
})
export type DeleteRelReq = z.infer<typeof deleteRelReq>

router.delete('/', async (req, res) => {
  const { creator, target } = util.checkReqBody(req.body, deleteRelReq)
  const ucanStore = await auth.checkReq(
    req,
    ucanCheck.hasAudience(SERVER_DID),
    ucanCheck.hasRelationshipsPermission(creator),
  )
  const db = util.getDB(res)
  const repo = await util.loadRepo(res, creator, ucanStore)
  await repo.relationships.unfollow(target)
  await db.deleteFollow(creator, target)
  await db.updateRepoRoot(creator, repo.cid)
  res.status(200).send()
})

// LIST

export const listRelReq = z.object({
  user: z.string(),
})
export type ListRelReq = z.infer<typeof listRelReq>

router.get('/list', async (req, res) => {
  const { user } = util.checkReqBody(req.query, listRelReq)
  const db = util.getDB(res)
  const follows = await db.listFollows(user)
  res.status(200).send(follows)
})

export default router
