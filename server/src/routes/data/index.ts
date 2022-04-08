import express from 'express'
import Root from './root.js'
import Repo from './repo.js'
import Post from './post.js'
import Interaction from './interaction.js'
import Relationship from './relationship.js'

const router = express.Router()

router.use('/root', Root)
router.use('/repo', Repo)
router.use('/post', Post)
router.use('/interaction', Interaction)
router.use('/relationship', Relationship)

export default router
