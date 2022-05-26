import * as ucan from 'ucans'
import { Chained, isCapabilityEscalation } from 'ucans'
import {
  writeCap,
  adxCapabilities,
  adxSemantics,
  maintenanceCap,
} from './capability.js'

type Check = (ucan: Chained) => Error | null

export const checkUcan = async (
  token: ucan.Chained,
  ...checks: Check[]
): Promise<Chained> => {
  for (let i = 0; i < checks.length; i++) {
    const maybeErr = checks[i](token)
    if (maybeErr !== null) {
      throw maybeErr
    }
  }

  return token
}

export const isRoot =
  () =>
  (token: Chained): Error | null => {
    if (token.proofs && token.proofs.length > 0) {
      throw new Error('Ucan is an attenuation and not the root')
    }
    return null
  }

export const hasAudience =
  (did: string) =>
  (token: Chained): Error | null => {
    if (token.audience() !== did) {
      return new Error('Ucan audience does not match server Did')
    }
    return null
  }

export const hasValidCapability =
  (rootDid: string, needed: ucan.Capability) =>
  (token: Chained): Error | null => {
    const neededAdx = adxSemantics.tryParsing(needed)
    if (neededAdx === null) {
      return new Error(`Could not parse a valid ADX capability`)
    }
    // the capability we need for the given action
    for (const cap of adxCapabilities(token)) {
      // skip over escalations
      if (isCapabilityEscalation(cap)) continue
      // check if this capability includes the one we need, if not skip
      const attempt = adxSemantics.tryDelegating(cap.capability, neededAdx)
      if (attempt === null || isCapabilityEscalation(attempt)) continue
      // check root did matches the repo's did
      if (cap.info.originator !== rootDid) {
        return new Error(
          `Posting permission does not come from the user's root DID: ${rootDid}`,
        )
      }
      // check capability is not expired
      if (cap.info.expiresAt < Date.now() / 1000) {
        return new Error(`Ucan is expired`)
      }
      // check capability is not too early
      if (cap.info.notBefore && cap.info.notBefore > Date.now() / 1000) {
        return new Error(`Ucan is being used before it's "not before" time`)
      }
      // all looks good, we return null 👍
      return null
    }
    // we looped through all options & couldn't find the capability we need
    return new Error(
      `Ucan does not permission the requested capability for user: ${neededAdx.resource} ${neededAdx.resource}`,
    )
  }

export const hasMaintenancePermission =
  (did: string) =>
  (token: Chained): Error | null => {
    const needed = maintenanceCap(did)
    return hasValidCapability(did, needed)(token)
  }

export const hasRelationshipsPermission =
  (did: string) =>
  (token: Chained): Error | null => {
    const needed = writeCap(did, 'relationships')
    return hasValidCapability(did, needed)(token)
  }

export const hasPostingPermission =
  (did: string, collection: string, record: string) =>
  (token: Chained): Error | null => {
    // the capability we need for the given post
    const needed = writeCap(did, collection, record)
    return hasValidCapability(did, needed)(token)
  }
