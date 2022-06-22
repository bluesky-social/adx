import express from 'express'
import cors from 'cors'
import axios from 'axios'
import * as uint8arrays from 'uint8arrays'
import * as ucan from 'ucans'
import * as crypto from '@adxp/crypto'

import KeyManagerDb from './db'
import { formatDidWeb } from './did'

const DID_SERVER = 'localhost:9999'

export const runServer = (
  db: KeyManagerDb,
  port: number,
): Promise<Express.Application> => {
  const app = express()
  app.use(cors())
  app.use(express.json())

  app.use((_req, res, next) => {
    res.locals.db = db
    next()
  })

  // request device ucan
  app.get('/ucan', async (req, res) => {
    const { did } = req.query
    const token = await ucan.Builder.create()
    res.send(200)
  })

  // create root keypair + DID
  app.post('/account', async (req, res) => {
    const { username } = req.body
    const did = `did:web:${encodeURIComponent(DID_SERVER)}:${username}`
    const keypair = await crypto.EcdsaKeypair.create({ exportable: true })
    const pubKey58 = uint8arrays.toString(keypair.publicKey, 'base58btc')
    const didDoc = formatDidWeb(did, pubKey58, 'idprovider.net') // @TODO: stand in id provider
    try {
      await axios.post(DID_SERVER, { didDoc })
    } catch (err) {
      return res
        .status(500)
        .send(`DID server did not accept DID registration: ${err}`)
    }
    const db: KeyManagerDb = res.locals.db
    await db.put(did, keypair)
    await res.send(200)
  })

  // request DID doc mutation

  return new Promise((resolve) => {
    app.listen(port, () => {
      console.log(
        `🔑 Key management server is running at http://localhost:${port}`,
      )
      resolve(app)
    })
  })
}

export default runServer
