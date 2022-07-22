import {knex, Knex} from 'knex'

export type Database = {
    tickForDid: ((did: string) => Promise<{ did: string; tid: string; tick: string } | undefined>),
    putTickForDid: ((
        did:string,
        tid:string,  // the new tid must me larger then the previous tid
        prevTid:string,  // gard: if the prevTid has changed the tick from the db is stale
        tick:string  // the tick is a json string
    ) => Promise<void>),
}

export const database = async (location: string): Promise<Database> =>  {
    const db = knex({
        client: 'sqlite3',
        connection: {
            filename: location,
        },
        useNullAsDefault: true,
    })

    if (!(await db.schema.hasTable('aic_ticks'))){
        await db.schema.createTable('aic_ticks', (table: Knex.CreateTableBuilder) => {
            table.string('did') // did the tick is for /did:aic:[2-7a-z]{16}/
            table.string('tid') // consensus tid if the tick /[2-7a-z]{4}-[2-7a-z]{3}-[2-7a-z]{4}-[2-7a-z]{2}/
            table.text('tick') // the tick signed by the consortium
            table.primary(['did', 'tid'])
        })
    }

    return {
        tickForDid: async (
            did: string,
          ): Promise<{ did: string; tid: string; tick: string } | undefined> => {
            return await db
              .select('did', 'tid', 'tick')
              .from('aic_ticks')
              .where({ did })
              .orderBy('tid', 'desc')
              .first()
        },
        putTickForDid: async (
            did: string,
            tid: string, // the tid for the tick being inserted
            prevTid: string | null, // the did for the tick being superseded
            tick: string, // the new tick
          ) => {
            // This is just a db wraper conferm that the tick is valid before calling
            // whereJsonPath('diff', '$.prev', '=', )
            if (prevTid === null) {
                await db('aic_ticks').insert({ did, tid, tick }) 
            } else {
              // the tid must be both
              // prevTid must be the greatest tid for that pid in the
              // note: we don't return failors the client must pull to learn they did upate the did
              await db('aic_ticks')
                .insert({ did, tid, tick })
                .whereExists(db('aic_ticks').max('tid').where(tid, prevTid))
            }
        }
    }
} 