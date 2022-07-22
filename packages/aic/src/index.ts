import * as crypto from '@adxp/crypto'
import { database, Database } from './db'
import { server } from './server'

const run = async () => {
  // create or open db
  const dbLoc = 'adx.sqlite'
  const port = 26979
  const db: Database = await database(dbLoc)
  console.log('Database:', dbLoc)

  // read the consortium key from secret store
  const CONSORTIUM_KEYPAIR = await crypto.EcdsaKeypair.import(
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
  const consortiumCrypto = {
    did: (): string => { return CONSORTIUM_KEYPAIR.did() },
    sign: async (msg:Uint8Array): Promise<Uint8Array> => {
      return await CONSORTIUM_KEYPAIR.sign(msg)
    },
    verifyDidSig: crypto.verifyDidSig,
  }

  const s = server(db, consortiumCrypto, port)
  s.on('listening', () => {
    console.log(`🌞 ADX AIC server is running at http://localhost:${port}`)
  })
}

run()
