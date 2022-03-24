import { Post, TID } from '@bluesky-demo/common'
import knex from 'knex'
import { CID } from 'multiformats'
import * as schema from './schema.js'
import { KnexDB } from './types'

export class Database {
  private db: KnexDB

  constructor(db: KnexDB) {
    this.db = db
  }

  static sqlite(location: string): Database {
    const db = knex({
      client: 'sqlite3',
      connection: {
        filename: location,
      },
    })
    return new Database(db)
  }

  static memory(): Database {
    return Database.sqlite(':memory:')
  }

  async createTables(): Promise<void> {
    await schema.createTables(this.db)
  }

  async dropTables(): Promise<void> {
    await schema.dropAll(this.db)
  }

  // USER DIDS
  // -----------

  async registerDid(username: string, did: string): Promise<void> {
    await this.db.insert({ username, did }).into('user_dids')
  }

  async getDidForUser(username: string): Promise<string | null> {
    const row = await this.db
      .select('did')
      .from('user_dids')
      .where('username', username)
    if (row.length < 1) return null
    return row[0].did
  }

  // REPO ROOTS
  // -----------

  async createRepoRoot(did: string, cid: CID): Promise<void> {
    await this.db.insert({ did, root: cid.toString() }).into('repo_roots')
  }

  async updateRepoRoot(did: string, cid: CID): Promise<void> {
    await this.db('repo_roots').where({ did }).update({ root: cid.toString() })
  }

  async getRepoRoot(did: string): Promise<CID | null> {
    const row = await this.db
      .select('root')
      .from('repo_roots')
      .where('did', did)
    return row.length < 1 ? null : CID.parse(row[0].root)
  }

  // POSTS
  // -----------

  async createPost(post: Post, cid: CID): Promise<void> {
    await this.db('microblog_posts').insert({
      ...post,
      cid: cid.toString(),
    })
  }

  async updatePost(post: Post, cid: CID): Promise<void> {
    const { tid, author, program, text, time } = post
    await this.db('repo_roots')
      .where({ tid, author, program })
      .update({ text, time, cid: cid.toString() })
  }

  async deletePost(
    tid: string,
    author: string,
    program: string,
  ): Promise<void> {
    await this.db('repo_roots').where({ tid, author, program }).delete()
  }
}

export default Database
