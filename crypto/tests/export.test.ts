import EcdsaKeypair from '../src/ecdsa.js'
import { verifyEcdsaSig } from '../src/verify.js'

describe('exports and reimports keys', () => {
  let keypair: EcdsaKeypair
  let imported: EcdsaKeypair

  it('has the same DID', async () => {
    keypair = await EcdsaKeypair.create({ exportable: true })
    const exported = await keypair.export()
    imported = await EcdsaKeypair.import(exported, { exportable: true })

    expect(keypair.did()).toBe(imported.did())
  })

  it('produces a valid signature', async () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    const sig = await imported.sign(data)

    const validSig = await verifyEcdsaSig(data, sig, keypair.did())
    expect(validSig).toBeTruthy()
  })
})
