import * as ucan from './ucans'
import { DidableKey } from './ucans'

import { adxSemantics, parseAdxResource } from './semantics'
import { MONTH_IN_SEC, YEAR_IN_SEC } from './consts'
import { Signer } from './types'
import { writeCap } from './capabilities'

export class AuthStore implements Signer {
  protected keypair: DidableKey
  protected ucanStore: ucan.Store

  constructor(keypair: DidableKey, ucanStore: ucan.Store) {
    this.keypair = keypair
    this.ucanStore = ucanStore
  }

  static async fromTokens(
    keypair: DidableKey,
    tokens: string[],
  ): Promise<AuthStore> {
    const ucanStore = await ucan.storeFromTokens(adxSemantics, tokens)
    return new AuthStore(keypair, ucanStore)
  }

  // Update these for sub classes
  // ----------------

  protected async getKeypair(): Promise<DidableKey> {
    return this.keypair
  }

  async addUcan(token: ucan.Ucan): Promise<void> {
    await this.ucanStore.add(token)
  }

  async getUcanStore(): Promise<ucan.Store> {
    return this.ucanStore
  }

  async clear(): Promise<void> {
    // noop
  }

  async reset(): Promise<void> {
    // noop
  }

  // ----------------

  async did(): Promise<string> {
    const keypair = await this.getKeypair()
    return keypair.did()
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const keypair = await this.getKeypair()
    return keypair.sign(data)
  }

  async findUcan(cap: ucan.Capability): Promise<ucan.Ucan | null> {
    const ucanStore = await this.getUcanStore()
    // we only handle adx caps right now
    const resource = parseAdxResource(cap.with)
    if (resource === null) return null
    const res = await ucan.first(
      ucanStore.findWithCapability(await this.did(), cap, resource.did),
    )
    if (!res) return null
    return res.ucan
  }

  async hasUcan(cap: ucan.Capability): Promise<boolean> {
    const found = await this.findUcan(cap)
    return found !== null
  }

  async createUcan(
    audience: string,
    cap: ucan.Capability,
    lifetime = MONTH_IN_SEC,
  ): Promise<ucan.Ucan> {
    const keypair = await this.getKeypair()
    const ucanStore = await this.getUcanStore()
    return ucan
      .createBuilder()
      .issuedBy(keypair)
      .toAudience(audience)
      .withLifetimeInSeconds(lifetime)
      .delegateCapability(cap, ucanStore)
      .build()
  }

  async createAwakeProof(
    audience: string,
    cap: ucan.Capability,
  ): Promise<ucan.Ucan> {
    const keypair = await this.getKeypair()
    const fullUcan = await this.findUcan(cap)
    if (!fullUcan) {
      throw new Error("Couldn't find ucan")
    }
    // gotta do the old fashioned API to build a token with no att
    return ucan.build({
      issuer: keypair,
      audience: audience,
      lifetimeInSeconds: 60 * 5,
      proofs: [ucan.encode(fullUcan)],
    })
  }

  // Claim a fully permissioned Ucan & add to store
  // Mainly for dev purposes
  async claimFull(): Promise<ucan.Ucan> {
    const keypair = await this.getKeypair()
    const ownDid = await this.did()
    const token = await ucan
      .createBuilder()
      .issuedBy(keypair)
      .toAudience(ownDid)
      .withLifetimeInSeconds(10 * YEAR_IN_SEC)
      .claimCapability(writeCap(ownDid))
      .build()
    await this.addUcan(token)
    return token
  }
}

export default AuthStore
