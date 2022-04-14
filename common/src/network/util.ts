import axios, {
  AxiosError,
  AxiosRequestConfig,
  AxiosRequestHeaders,
} from 'axios'
import * as ucan from 'ucans'

export const assureAxiosError = (err: unknown): AxiosError => {
  if (axios.isAxiosError(err)) return err
  throw err
}

export const authHeader = (token: ucan.Chained): AxiosRequestHeaders => {
  return {
    Authorization: `Bearer ${token.encoded()}`,
  }
}

export const authCfg = (token: ucan.Chained): AxiosRequestConfig => {
  return {
    headers: authHeader(token),
  }
}

// this will be self describing from the DID, so we hardwire this for now & make it an env variable
export const didNetworkUrl = (): string => {
  const envVar = process.env.DID_NETWORK_URL
  if (typeof envVar === 'string') {
    return envVar
  }
  return 'http://localhost:2583/did-network'
}
