import { sha256 } from '@adxp/crypto'
import * as uint8arrays from 'uint8arrays'
import { canonicaliseDocumentToUint8Array } from './signature'
import { Document, TidString } from './types'

// @TODO move this to "@adxp/common/src/common/util"
const S32_CHAR = '234567abcdefghijklmnopqrstuvwxyz'
const B32_CHAR = 'abcdefghijklmnopqrstuvwxyz234567'

// @TODO move this to "@adxp/common/src/common/util"
export const pid = async (
  data: Uint8Array | string | Document,
): Promise<string> => {
  if (data instanceof Uint8Array) {
    // return the pid120 a 24 char pid
    const hash = s32encode(await sha256(data))
    let twos = 0
    for (twos = 0; twos < 32; twos++) {
      if (hash[twos] !== '2') {
        break
      }
    }
    const head = S32_CHAR[31 - twos]
    const tail = hash.slice(twos, twos + 15) // 23 for pid120; 15 for pid80 // Are we ok with 80 bits?
    return head + tail
  }
  if (typeof data === 'string') {
    return pid(uint8arrays.fromString(data))
  }
  return pid(canonicaliseDocumentToUint8Array(data))
}

const s32encode = (data: Uint8Array): string => {
    // this is gross so many alocatons and funtion calls :(
    const base32 = uint8arrays.toString(data, 'base32')
    const sort_order_invariant_base32 = base32.split('').map((c) => {
      return S32_CHAR[B32_CHAR.indexOf(c)]
    })
    return sort_order_invariant_base32.join('')
  }

const tidToSec = (tid: TidString): number => {
  // 3j5s-z6d-c2hy-22
  // 3j5s-z6d first 7 char represent ~ seconds
  const s = tid.replace(/-/g, '')
  return (((((((
    S32_CHAR.indexOf(s[0])) * 32 + 
    S32_CHAR.indexOf(s[1])) * 32 + 
    S32_CHAR.indexOf(s[2])) * 32 + 
    S32_CHAR.indexOf(s[3])) * 32 + 
    S32_CHAR.indexOf(s[4])) * 32 + 
    S32_CHAR.indexOf(s[5])) * 32 + 
    S32_CHAR.indexOf(s[6]))
}

const tidDifferenceSeconds = (tid1:TidString, tid2:TidString): number => {
  return tidToSec(tid1) - tidToSec(tid2)
}

export const tidDifferenceHours = (tid1:TidString, tid2:TidString): number => {
  return tidDifferenceSeconds(tid1, tid2) / 60 / 60
}