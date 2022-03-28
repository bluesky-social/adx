import express from 'express'
import { z } from 'zod'
import * as util from '../../util.js'
import { ServerError } from '../../error.js'
import { schema, check, TID } from '@bluesky-demo/common'

const router = express.Router()

// GET INTERACTION
// --------------

export const getInteractionReq = z.object({
  did: z.string(),
  program: z.string(),
  tid: z.string(),
})
export type GetInteractionReq = z.infer<typeof getInteractionReq>

router.get('/', async (req, res) => {
  if (!check.is(req.query, getInteractionReq)) {
    throw new ServerError(400, 'Poorly formatted request')
  }
  const { did, program, tid } = req.query
  const repo = await util.loadRepo(res, did)
  const interCid = await repo.runOnProgram(program, async (store) => {
    return store.interactions.getEntry(TID.fromStr(tid))
  })
  if (interCid === null) {
    throw new ServerError(404, 'Could not find interaction')
  }
  const like = await repo.get(interCid, schema.microblog.like)
  res.status(200).send(like)
})

// CREATE INTERACTION
// --------------

export const createInteractionReq = schema.microblog.like
export type CreateInteractionReq = z.infer<typeof createInteractionReq>

router.post('/', async (req, res) => {
  if (!check.is(req.body, createInteractionReq)) {
    throw new ServerError(400, 'Poorly formatted request')
  }
  const like = req.body
  const repo = await util.loadRepo(res, like.author)
  const likeCid = await repo.put(like)
  await repo.runOnProgram(like.program, async (store) => {
    return store.interactions.addEntry(TID.fromStr(like.tid), likeCid)
  })
  const db = util.getDB(res)
  await db.updateRepoRoot(like.author, repo.cid)
  await db.createLike(like, likeCid)
  res.status(200).send()
})

// DELETE INTERACTION
// --------------

export const deleteInteractionReq = z.object({
  did: z.string(),
  program: z.string(),
  tid: z.string(),
})
export type DeleteInteractionReq = z.infer<typeof deleteInteractionReq>

router.delete('/', async (req, res) => {
  if (!check.is(req.params, deleteInteractionReq)) {
    throw new ServerError(400, 'Poorly formatted request')
  }
  const { did, program, tid } = req.params
  const repo = await util.loadRepo(res, did)
  await repo.runOnProgram(program, async (store) => {
    return store.interactions.deleteEntry(TID.fromStr(tid))
  })
  const db = util.getDB(res)
  await db.updateRepoRoot(did, repo.cid)
  await db.deleteLike(did, program, tid)
  res.status(200).send()
})

export default router
