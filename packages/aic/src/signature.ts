import * as uint8arrays from 'uint8arrays'
import { Document, ErrorMessage, Asymmetric } from "./types"

export const canonicaliseDocumentToUint8Array = (
    document: Document,
  ): Uint8Array => {
    // @TODO canonicalise json/cbor?
    // JSON Canonicalization Scheme (JCS)
    // https://datatracker.ietf.org/doc/html/rfc8785
    return uint8arrays.fromString(JSON.stringify(document))
  }

export const sign = async (doc: Document, key: Asymmetric) => {
    if (doc.key !== key.did()) {
      throw Error('Info: passed in secret key and did do not match')
    }
    doc['sig'] = ''
    const data = canonicaliseDocumentToUint8Array(doc)
    const sig = await key.sign(data)
    // https://github.com/multiformats/multihash
    doc['sig'] = 'z' + uint8arrays.toString(sig, 'base58btc')
    return doc
  }

export const validateSig = async (
  doc: Document,
  key: Asymmetric,
): Promise<boolean | ErrorMessage> => {
  if (
      typeof doc.sig !== 'string' ||
      typeof doc.key !== 'string' ||
      doc.key.length < 1
  ) {
      return false
  }

  const doc_copy = JSON.parse(JSON.stringify(doc))
  if (doc_copy.sig[0] !== 'z') {
      // check the multibase https://github.com/multiformats/multibase
      throw "signatures must be 'z'+ base58btc" // maby just retuen false?
  }
  doc_copy.sig = ''
  const data = canonicaliseDocumentToUint8Array(doc_copy)


  const sig = uint8arrays.fromString(doc.sig.slice(1), 'base58btc')
  let valid = await key.verifyDidSig(doc.key, data, sig)
  return valid // @TODO check that the key is in the did doc
}