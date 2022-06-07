#!/usr/bin/env node

import server from './server.js'

const envPort = process.env.PORT
const port = envPort ? parseInt(envPort) : 3005

server(port)
console.log(`🔁 Relay server running on port ${port}`)
