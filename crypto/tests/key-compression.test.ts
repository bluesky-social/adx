import EcdsaKeypair from '../src/ecdsa.js'
import * as cryptoUtil from '../src/util.js'

describe('public key compression', () => {
  let keypair: EcdsaKeypair
  let compressed: Uint8Array

  it('compresses a key to the correct length', async () => {
    keypair = await EcdsaKeypair.create()
    compressed = cryptoUtil.compressPubkey(keypair.publicKey)
    expect(compressed.length).toBe(33)
  })

  it('decompresses a key to the original', async () => {
    const decompressed = cryptoUtil.decompressPubkey(compressed)
    expect(decompressed.length).toBe(65)
    expect(decompressed).toEqual(keypair.publicKey)
  })

  it('works consistently', async () => {
    const pubkeys: Uint8Array[] = []
    for (let i = 0; i < 1000; i++) {
      const key = await EcdsaKeypair.create()
      pubkeys.push(key.publicKey)
    }
    const compressed = pubkeys.map(cryptoUtil.compressPubkey)
    const decompressed = compressed.map(cryptoUtil.decompressPubkey)
    expect(pubkeys).toEqual(decompressed)
  })
})
