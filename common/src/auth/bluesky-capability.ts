import {
  capabilities,
  Capability,
  CapabilitySemantics,
  CapabilityEscalation,
  Chained,
  isCapabilityEscalation,
} from 'ucans'
import TID from '../repo/tid'
import { Collection } from '../repo/types'

/*
Bluesky Ucans:

Resource name: 'bluesky'

- Full permission for account: 
    did:bsky:userDid|*
- Permission to write to particular program namespace: 
    did:bsky:userDid|did:bsky:microblog|*
- Permission to make only interactions in a given namespace:
    did:bsky:userDid|did:bsky:microblog|interactions|*
- Permission to create a single interaction on user's behalf: 
    did:bsky:userDid|did:bsky:microblog|interactions|234567abcdefg

Example: 
{
  bluesky: 'did:bsky:abcdefg|did:bsky:microblog|*'
  cap: 'WRITE'
}

At the moment, for demonstration purposes, we support only one capability level: "WRITE"
*/

export const BlueskyAbilityLevels = {
  MAINTAINANCE: 0,
  WRITE: 1,
}
export type BlueskyAbility = keyof typeof BlueskyAbilityLevels

export const isBlueskyAbility = (
  ability: string,
): ability is BlueskyAbility => {
  return ability === 'MAINTAINANCE' || ability === 'WRITE'
}

export interface BlueskyCapability extends Capability {
  bluesky: string
  cap: BlueskyAbility
}

export const blueskySemantics: CapabilitySemantics<BlueskyCapability> = {
  tryParsing(cap: Capability): BlueskyCapability | null {
    if (typeof cap.bluesky === 'string' && isBlueskyAbility(cap.cap)) {
      return {
        bluesky: cap.bluesky,
        cap: cap.cap,
      }
    }
    return null
  },

  tryDelegating(
    parentCap: BlueskyCapability,
    childCap: BlueskyCapability,
  ): BlueskyCapability | null | CapabilityEscalation<BlueskyCapability> {
    if (
      BlueskyAbilityLevels[childCap.cap] > BlueskyAbilityLevels[parentCap.cap]
    ) {
      return {
        escalation: 'Capability level escalation',
        capability: childCap,
      }
    }

    const [childDid, childProgram, childCollection, childTid] =
      childCap.bluesky.split('|')
    const [parentDid, parentProgram, parentCollection, parentTid] =
      parentCap.bluesky.split('|')

    if (childDid !== parentDid) {
      return null
    }

    if (parentProgram === '*') {
      return childCap
    } else if (childProgram === '*') {
      return namespaceEscalation(childCap)
    } else if (childProgram !== parentProgram) {
      return null
    }

    if (parentCollection === '*') {
      return childCap
    } else if (childCollection === '*') {
      return namespaceEscalation(childCap)
    } else if (childCollection !== parentCollection) {
      return null
    }

    if (parentTid === '*') {
      return childCap
    } else if (childTid === '*') {
      return namespaceEscalation(childCap)
    } else if (childTid !== parentTid) {
      return null
    }
    // they totally match
    return childCap
  },
}

export const hasPermission = (
  parent: BlueskyCapability,
  child: BlueskyCapability,
): boolean => {
  const attempt = blueskySemantics.tryDelegating(parent, child)
  return attempt !== null && !isCapabilityEscalation(attempt)
}

export const namespaceEscalation = (cap: BlueskyCapability) => {
  return {
    escalation: 'Bluesky program namespace esclation',
    capability: cap,
  }
}

export const collectionEscalation = (cap: BlueskyCapability) => {
  return {
    escalation: 'Bluesky collection esclation',
    capability: cap,
  }
}

export const tidEscalation = (cap: BlueskyCapability) => {
  return {
    escalation: 'Bluesky TID esclation',
    capability: cap,
  }
}

export function blueskyCapability(
  did: string,
  program?: string,
  collection?: Collection,
  tid?: TID,
): BlueskyCapability {
  let resource = did
  if (program) {
    resource += '|' + program
  }
  if (collection) {
    resource += '|' + collection
  }
  if (tid) {
    resource += '|' + tid.toString()
  } else {
    resource += '|*'
  }
  return {
    bluesky: resource,
    cap: 'WRITE',
  }
}

export function blueskyCapabilities(ucan: Chained) {
  return capabilities(ucan, blueskySemantics)
}
