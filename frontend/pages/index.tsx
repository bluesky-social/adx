import styles from "@components/App.module.scss";

import * as React from "react";

import { service, UserStore, LocalUser, Post } from '@bluesky-demo/common'
import * as ucan from 'ucans'

import App from "@components/App"
import Register from "@components/Register"

function Home(props: {}) {
  const [localUser, setLocalUser] = React.useState<LocalUser | null>(null);
  const [store, setStore] = React.useState<UserStore | null>(null);
  const [posts, setPosts] = React.useState<Post[]>([]);
  const [tweet, setTweet] = React.useState<string>('');
  const [loading, setLoading] = React.useState<boolean>(true);

  const addPost = async (post: Post) => {
    await store.addPost(post)
    const car = await store.getCarFile()
    const twitterDid = await service.getServerDid()
    const token = await ucan.build({
      audience: twitterDid,
      issuer: localUser.keypair,
      capabilities: [{
        'twitter': localUser.username,
        'cap': 'POST'
      }]
    })
    await service.updateUser(car, ucan.encode(token))
    setPosts(store.posts)
  }

  const loadPosts = async () => {
    if(localUser === null) return 
    let userStore: UserStore
    try {
      const car = await service.fetchUser(localUser.keypair.did())
      userStore = await UserStore.fromCarFile(car, localUser.keypair)
    } catch (_err) {
      userStore = await createNewStore()
    }
    setStore(userStore)
    setPosts(userStore.posts)
  }

  const createNewStore = async (): Promise<UserStore> => {
    const userStore = await UserStore.create(localUser.username, localUser.keypair)

    if(userStore.posts.length === 0) {
      const testPost = {
        user: localUser.username,
        text: 'hello world!'
      }
      await userStore.addPost(testPost)
    } 

    return userStore
  }

  const updateTweet = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setTweet(e.target.value)
  }

  const loadLocalUser = async () => {
    const username =  localStorage.getItem('username')
    const secretKey = localStorage.getItem('secretKey')
    if(!username || !secretKey) {
      setLoading(false)
      return
    }

    const keypair = ucan.EdKeypair.fromSecretKey(secretKey, { format: 'base64pad' })
    const registeredDid = await service.fetchUserDid(username)

    // check if server has been reset & frontend cache is out of date
    if(!registeredDid || keypair.did() !== registeredDid) {
      localStorage.clear()
      setLoading(false)
      return
    }

    setLoading(false)
    setLocalUser({ username, keypair })
  }

  const postTweet = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    addPost({
      user: localUser.username,
      text: tweet
    });
  }

  React.useEffect(() => {
    loadLocalUser()
  }, [])

  React.useEffect(() => {
    loadPosts();
  }, [localUser]);

  if (loading) {
    return null
  }

  if (localUser === null) {
    return (
      <App>
        <Register onRegister={setLocalUser} />
      </App>
    )
  }

  return (
    <App>
      <div className={styles.header}>
        <p className={styles.paragraph}>Logged in as <strong>{localUser.username}</strong></p>
        <p className={styles.paragraph}>Putting posts in IPFS.</p>
        <form onSubmit={postTweet}>
          <textarea onChange={updateTweet} className={styles.tweetBox}/>
          <br/>
          <button className={styles.button} type='submit'>Post</button>
        </form>
        <br/>
      </div>
      <div className={styles.tweets}>
        <ul>
          {posts.map((post, i) => {
            return (
              <div className={styles.post} key={i}>
                <p className={styles.postUser}>{post.user}</p>
                <p> {post.text} </p>
              </div>
            ) ;
          })}
        </ul>
      </div>
  </App>
  );
}

export default Home;