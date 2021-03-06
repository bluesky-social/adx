import dotenv from 'dotenv'
import { StartParams, ServerType, ServerConfig } from './types.js'

const getPorts = (type: ServerType, name: string): ServerConfig[] => {
  const portsStr = process.env[name]
  if (!portsStr) return []
  return portsStr
    .split(',')
    .map((str) => parseInt(str))
    .filter(Boolean)
    .map((port) => ({ type, port }))
}

export function load(): StartParams {
  dotenv.config()

  return {
    servers: [
      ...getPorts(ServerType.PersonalDataServer, 'PERSONAL_DATA_SERVERS'),
      ...getPorts(ServerType.WebSocketRelay, 'WEB_SOCKET_RELAY'),
      ...getPorts(ServerType.DidWebHost, 'DID_WEB_HOST'),
      ...getPorts(ServerType.KeyManager, 'KEY_MANAGER'),
      ...getPorts(ServerType.AuthLobby, 'AUTH_LOBBYS'),
      ...getPorts(ServerType.ExampleApp, 'EXAMPLE_APPS'),
    ],
  }
}
