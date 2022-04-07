import cmd from '../../lib/command.js'
import { loadDelegate } from '../../lib/client.js'
import { REPO_PATH } from '../../lib/env.js'
import { TID } from '@bluesky-demo/common'

export default cmd({
  name: 'like',
  category: 'interactions',
  help: 'Like a post.',
  args: [{ name: 'author' }, { name: 'post_id' }],
  opts: [],
  async command(args) {
    const author = args._[0]
    const tid = TID.fromStr(args._[1])
    const client = await loadDelegate(REPO_PATH)
    const like = await client.likePost(author, tid)
    const likeTid = TID.fromStr(like.tid)
    console.log(`Created like: `, likeTid.formatted())
  },
})
