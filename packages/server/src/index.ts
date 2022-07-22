import dotenv from 'dotenv'
import { IpldStore } from '@adxp/common'
import * as crypto from '@adxp/crypto'
import Database from './db/index'
import server from './server'

const run = async () => {
  const env = process.env.ENV
  if (env) {
    dotenv.config({ path: `./.${env}.env` })
  } else {
    dotenv.config()
  }

  let blockstore: IpldStore
  let db: Database

  const bsLoc = process.env.BLOCKSTORE_LOC
  const dbLoc = process.env.DATABASE_LOC

  if (bsLoc) {
    blockstore = IpldStore.createPersistent(bsLoc)
  } else {
    blockstore = IpldStore.createInMemory()
  }

  if (dbLoc) {
    console.log('Database:', dbLoc)
    db = Database.sqlite(dbLoc)
  } else {
    db = Database.memory()
  }

  db.createTables()

  const keypair = await crypto.EcdsaKeypair.create()

  const envPort = parseInt(process.env.PORT || '')
  const port = isNaN(envPort) ? 2583 : envPort

  const s = server(blockstore, db, keypair, port)
  s.on('listening', () => {
    console.log(`🌞 ADX Data server is running at http://localhost:${port}`)
  })
}

run()
