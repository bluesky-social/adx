import {
  AdxRecordValidator,
  AdxRecordValidatorDescription,
} from '@adxp/schemas'
import * as auth from '@adxp/auth'
import { GetRecordResponse } from './http-types.js'

export type SchemaOpt =
  | string
  | string[]
  | AdxRecordValidator
  | AdxRecordValidatorDescription
  | '*'

export interface AdxClientOpts {
  pds?: string
  locale?: string
  schemas?: any[]
}

export interface RegisterRepoParams {
  did: string
  username: string
  authStore: auth.AuthStore
}

export interface GetRecordResponseValidated extends GetRecordResponse {
  valid?: boolean
  fullySupported?: boolean
  incompatible?: boolean
  error?: string | undefined
  fallbacks?: string[] | undefined
}

export interface BatchWrite {
  action: 'create' | 'put' | 'del'
  collection: string
  key?: string
  value?: any
}
