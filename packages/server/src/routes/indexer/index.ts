import express from 'express'
import Timeline from './timeline'
import Feed from './feed'
import PostInfo from './post-info'
import Count from './count'
import Followers from './followers'
import AccountInfo from './account-info'

const router = express.Router()

router.use('/timeline', Timeline)
router.use('/feed', Feed)
router.use('/post-info', PostInfo)
router.use('/count', Count)
router.use('/followers', Followers)
router.use('/account-info', AccountInfo)

export default router
