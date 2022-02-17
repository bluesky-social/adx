import { CID } from "multiformats"
import * as check from "../type-check.js"

import IpldStore from "../blockstore/ipld-store.js"
import { IdMapping } from "../types.js"
import SSTable, { TableSize } from "./ss-table.js"
import Timestamp from "../timestamp.js"

export class Branch {

  store: IpldStore
  cid: CID
  data: IdMapping

  constructor(store: IpldStore, cid: CID, data: IdMapping) {
    this.store = store
    this.cid = cid
    this.data = data
  }

  static async create(store: IpldStore): Promise<Branch> {
    const cid = await store.put({})
    return new Branch(store, cid, {})
  }

  static async get(store: IpldStore, cid: CID): Promise<Branch> {
    const data = await store.get(cid, check.assureIdMapping)
    return new Branch(store, cid, data)
  }

  async getOrCreateCurrTable(): Promise<{ table: SSTable, name: Timestamp | null}> {
    const curr = await this.getCurrTable()
    if (curr) {
      if (!curr.table.isFull()) {
        return curr
      } else {
        await this.compressTables()
      }
    } 

    return {
      table: await SSTable.create(this.store),
      name: null
    }
  }

  async getCurrTable(): Promise<{ table: SSTable, name: Timestamp} | null> {
    const key = this.keys()[0]
    if (key === undefined) return null
    const table = await this.getTable(key)
    if (table === null) return null
    return {
      table: table,
      name: key
    }
  }

  async getTable(timestamp: Timestamp): Promise<SSTable | null> {
    if (!timestamp) return null
    const cid = this.data[timestamp.toString()]
    if (cid === undefined) return null
    return SSTable.get(this.store, cid)
  }

  async findTableForKey(timestamp: Timestamp): Promise<SSTable | null> {
    const key = this.keys().find(k => timestamp.compare(k) >= 0)
    if (!key) return null
    return this.getTable(key)
  }

  async updateRoot(): Promise<void> {
    this.cid = await this.store.put(this.data)
  }

  async compressTables(): Promise<void> {
    const keys = this.keys()
    if (keys.length < 1) return
    const mostRecent = await this.getTable(keys[0])
    if (mostRecent === null) return 
    const compressed = await this.compressCascade(mostRecent, keys.slice(1))
    const tableName = compressed.oldestKey()
    if (tableName && tableName.compare(keys[0]) !== 0 ) {
      delete this.data[keys[0].toString()]
      this.data[tableName.toString()] = compressed.cid
    }
    await this.updateRoot()
  }

  private async compressCascade(mostRecent: SSTable, nextKeys: Timestamp[]): Promise<SSTable> {
    const size = mostRecent.size
    const keys = nextKeys.slice(0,3)
    const tables = await Promise.all(
      keys.map(k => this.getTable(k))
    )
    const filtered = tables.filter(t => t?.size === size) as SSTable[]
    // need 4 tables to merge down a level
    if (filtered.length < 3 || size === TableSize.xl) {
      // if no merge at this level, we just write the previous level & bail
      return mostRecent
    }

    keys.forEach(k => delete this.data[k.toString()])
    
    const merged = await SSTable.merge([mostRecent, ...filtered])
    return await this.compressCascade(merged, nextKeys.slice(3))
  }

  async addEntry(timestamp: Timestamp, cid: CID): Promise<void> {
    const curr = await this.getOrCreateCurrTable()
    const oldestKey = curr.table.oldestKey()
    if (oldestKey && timestamp.compare(oldestKey) < 0) {
      // @TODO handle this more gracefully
      throw new Error("Attempting to add an id that is too old for the table")
    }
    await curr.table.addEntry(timestamp, cid)
    const name = curr.name?.toString() || timestamp.toString()
    this.data[name] = curr.table.cid
    await this.updateRoot()
  }

  async editEntry(timestamp: Timestamp, cid: CID): Promise<void> {
    const table = await this.findTableForKey(timestamp)
    if (!table) throw new Error(`Could not find entry with id: ${timestamp}`)
    return table.editEntry(timestamp, cid)
  }

  async removeEntry(timestamp: Timestamp): Promise<void> {
    const table = await this.findTableForKey(timestamp)
    if (!table) throw new Error(`Could not find entry with id: ${timestamp}`)
    return table.removeEntry(timestamp)
  }

  keys(): Timestamp[] {
    return Object.keys(this.data).sort().reverse().map(k => Timestamp.parse(k))
  }

  cids(): CID[] {
    return Object.values(this.data).sort().reverse()
  }

  async nestedCids(): Promise<CID[]> {
    const cids = this.cids()
    const tableCids = await Promise.all(
      this.cids().map(async c => {
        const table = await SSTable.get(this.store, c)
        return table.cids()
      })
    )
    return [...cids, ...tableCids.flat()]
  }
}

export default Branch