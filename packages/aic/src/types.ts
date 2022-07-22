export type ErrorMessage = {
    error: string
    cause?: ErrorMessage
    [key: string]: Value
  }
  
export type Value =
    | null
    | boolean
    | number
    | string
    | Value[]
    | { [key: string]: Value }
    | undefined

export type TidString = string
export type Signature = string
export type DidKeyString = string
export type Patch = ['put' | 'del', (string | number)[], Value]
export type Diff = {
    prev: TidString
    patches: Patch[]
    key: DidKeyString
    sig: Signature
}
export type Diffs = { [index: string]: Document | Diff } // the first diff is arbatrary JSON object initial value
export type Tick = {
    tid: TidString
    did: string
    diffs: Diffs
    key: DidKeyString
    sig: Signature
}

export type Document = { [key: string]: Value }

export type Asymmetric = {
    did: () => DidKeyString // publkey
    verifyDidSig: (did: DidKeyString, data: Uint8Array, sig: Uint8Array) => Promise<boolean>
    sign: (msg: Uint8Array) => Promise<Uint8Array> // closure over secret key
}