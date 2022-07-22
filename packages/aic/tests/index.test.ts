import {
  diffsToDidDoc,
  sign,
  validateSig,
  tickFromDiffs,
  updateTick,
  tickToDidDoc,
} from '../src/document'
import { pid } from '../src/pid'
import { EcdsaKeypair, verifyDidSig } from '@adxp/crypto'
import * as uint8arrays from 'uint8arrays'
import { TID } from '@adxp/common'
import { Diff, Document, Tick, Asymmetric } from '../src/types'

const keyConsortium = EcdsaKeypair.import(
  {
    // did:key:zDnaeeL44gSLMViH9khhTbngNd9r72MhUPo4WKPeSfB8xiDTh
    key_ops: [ 'sign' ],
    ext: true,
    kty: 'EC',
    x: 'zn_OWx4zJM5zy8E_WUAJH9OS75K5t6q74D7lMf7AmnQ',
    y: 'trzc_f9i_nOuYRCLMyXxBcpc3OVlylmxdESQ0zdKHeQ',
    crv: 'P-256',
    d: 'Ii__doqqQ5YYZLfKh-LSh1Vm6AqCWHGMrBTDYKaEWfU',
  },
  {
    exportable: true,
  },
)

let consortiumCrypto: Asymmetric | null = null
let accountCrypto: Asymmetric | null = null

const keyTick = EcdsaKeypair.import(
  {
    // did:key:zDnaenyrpzvz4VNQVRTSRUwQWM8wLNcUeh1mmoBiTb1PLQrht
    key_ops: [ 'sign' ],
    ext: true,
    kty: 'EC',
    x: 'Twyq87vXIh8MEbj02V8scuY3uVGK6FUv9uPi2guD268',
    y: 'OrG4Yt23_smcwVnN6kzjdcTAWRNkS_R0rUxQwVk88QM',
    crv: 'P-256',
    d: 'FnLpO2CNkLP-D2ZhOPwBjeyFCnPQM6G4wXBhDQcgu1Q'
  },
  {
    exportable: true,
  },
)

const keyAccount = EcdsaKeypair.import(
  {
    // did:key:zDnaeycJUNQugcrag1WmLePtK9agLYLyXvscnQM4FHm1ASiRV
    key_ops: [ 'sign' ],
    ext: true,
    kty: 'EC',
    x: '7PdxOiABSKrek0it0485i1l6qwL7Mjbw_IChbeCNMsg',
    y: 'Ir1RRiNCrxLCcKMSsvaKBiA8Lt5NNyea5WcgqCR1OM8',
    crv: 'P-256',
    d: 'URhLRG1NE10xz0HCWUESwaT8KahrHsX4KNW7sLKsQxw',
  },
  {
    exportable: true,
  },
)

const keyRecovery = EcdsaKeypair.import(
  {
    // did:key:zDnaepvdtQ3jDLU15JihZwmMghuRugJArN8x9rm6Czt9BkHEM  
    key_ops: [ 'sign' ],
    ext: true,
    kty: 'EC',
    x: 'dLiYUIcjLiBo7p7Ve6k8ts_IZ8sRlk5Sarx14UD95W0',
    y: 'LP5TyYkAVRVXFSMq_izgYLHg6MTprsSEsANS6hF-qeo',
    crv: 'P-256',
    d: 'KXpzn4Tuo9YEVTm_HMqy2w_LukGhqK4Ql21Q8wcAHHc',
  },
  {
    exportable: true,
  },
)

describe('aic test test', () => {
  beforeAll(async () => {
    const keyc = (await keyConsortium)
    consortiumCrypto = {
      did: (): string => {return keyc.did()},
      sign: async (msg:Uint8Array): Promise<Uint8Array> => {
        return await (await keyConsortium).sign(msg)
      },
      verifyDidSig: verifyDidSig,
    }
    const key2 = (await keyAccount)
    accountCrypto = {
      did: (): string => {return key2.did()},
      sign: async (msg:Uint8Array): Promise<Uint8Array> => {
        return await (await keyAccount).sign(msg)
      },
      verifyDidSig: verifyDidSig,
    }
    keyAccount
  })

  it('works', async () => {
    console.log(TID.next().formatted())
    console.log(await (await EcdsaKeypair.create({exportable: true})).export())
    // console.log('keyConsortium', (await keyConsortium).did())
    // console.log('keyTick', (await keyTick).did())
    // console.log('keyAccount', (await keyAccount).did())
    // console.log('keyRecovery', (await keyRecovery).did())

    // const c = await keyConsortium
    // const f = (msg) =>{return c.sign(msg)}
    // console.log('f', await f(new Uint8Array()))
    expect(true)
  })


// old test to migrate.

  it('diffsToDoc basic test 1', async () => {
    const diffsDoc = {
      '3j55-hih-g24c-22': {
        a: 1,
        b: 2,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      },
      '3j55-hiu-hcxs-22': {
        prev: '3j55-hih-g24c-22',
        patches: [['put', ['d'], 4]],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'z58kG77wksPLi8185y6fsJG3NidUjYVBzBKVqSG3T5NQKwrNu9d6aL2UorPRzre4VCvKUASuec53jain2LRaMCtmZ',
      },
      '3j55-hk2-pbqk-22': {
        prev: '3j55-hiu-hcxs-22',
        patches: [['del', ['b']]],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'z45gdspAmr9W1tC2KCBrnugdQSXP7fbTUvxz8yM1QnPPNLTKHs2PWzDYgmJe8RPLhZKrfpVFEsvaCMHkhLkFGfxRo',
      },
      '3j55-hki-vs6w-22': {
        prev: '3j55-hk2-pbqk-22',
        patches: [['put', ['e', 'ea'], 'each']],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'z66WkmrsuVNiqBT3mhjF8G5MNcgpcKbCvXYinqFL73xYkwbSRvNNE7Mj8ak9gEN5FCkamWgsa82GrG984sJxcJdw8',
      },
      '3j55-hl6-3ctt-22': {
        prev: '3j55-hk2-pbqk-22',
        patches: [['put', ["Don't", 'put', 'me'], 'in']],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'z5oHy2qCSKR9Z9hXuha6c7qEpUWMzGNeZcj8D5kDAxsWP6P8FN4kmSWHcoLv4q5umiyMWcUk5CePGeh51khRGEgGL',
      },
    }

  expect(
    await diffsToDidDoc(diffsDoc, consortiumCrypto as Asymmetric)
  ).toEqual(
    {
      id: 'did:aic:zkug3v3btzimdf4d',
      a: 1,
      c: 3,
      d: 4,
      e: { ea: 'each' },
      'adx/account_keys': [
        'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
      ],
   }
  )
})

  it('diffsToDoc init test', async () => {
    const diffsDoc = {
      '2': {
        a: 1,
        b: 2,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      },
    }
    expect(
      await diffsToDidDoc(diffsDoc, consortiumCrypto as Asymmetric),
    ).toEqual(
      {
        id: 'did:aic:zkug3v3btzimdf4d',
        a: 1,
        b: 2,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      }
    )
  })

  it('diffsToDoc put test', async () => {
    const diffsDoc = {
      '2': {
        a: 1,
        b: 2,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      },
      '3': {
        prev: '2',
        patches: [['put', ['d'], 4]],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'z3X32k2MrDtWLr56qzGrpgCdLUouZGXZLCca1RH8unoF97geJpedbWAD8pnbw2KRM7qXLupPcurTNRAdPLAVqxP7u',
      },
    }
    expect(
      await diffsToDidDoc(diffsDoc, consortiumCrypto as Asymmetric),
    ).toEqual(
      {
        id: 'did:aic:zkug3v3btzimdf4d',
        a: 1,
        b: 2,
        c: 3,
        d: 4,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      }
    )
  })

  it('diffsToDoc del test', async () => {
    const diffsDoc = {
      '2': {
        a: 1,
        b: 2,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      },
      '3': {
        prev: '2',
        patches: [['del', ['b']]],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'zsXdHvXFyrZQ5dtmtaEcPVbwSgMFZWznp3V8SJGUEVPWengoo1N4tsDgcvC6e2ZwiHvWekdjLmo2o2XLJfoErstN',
      },
    }
    expect(
      await diffsToDidDoc(diffsDoc, consortiumCrypto as Asymmetric),
    ).toEqual(
      {
        id: 'did:aic:zkug3v3btzimdf4d',
        a: 1,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      }
    )
  })

  it('diffsToDidDoc skip bad prev test', async () => {
    const diffsDoc = {
      '2': {
        a: 1,
        b: 2,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      },
      '3': {
        prev: '1',
        patches: [['del', ['b']]],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'z3wZ4j3HoKaAPfv1eTTeknCYsUbjfkbzs7qQkyaqVqBi4iNbvA16A9totDJfRaZZ5PxVwHrFBgCs4BGvns6a5TAp',
      },
    }
    expect(
      await diffsToDidDoc(diffsDoc, consortiumCrypto as Asymmetric),
    ).toEqual(
      {
        id: 'did:aic:zkug3v3btzimdf4d',
        a: 1,
        b: 2,
        c: 3,
        'adx/account_keys': [
          'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        ],
      }
    )
  })

  it('diffsToDidDoc test key gen', async () => {
    //gen key
    const key = await EcdsaKeypair.create({ exportable: true })
    const crypto = {
      did: (): string => {return key.did()},
      sign: async (msg:Uint8Array): Promise<Uint8Array> => { return await key.sign(msg) },
      verifyDidSig: verifyDidSig,
    }
    // console.log(await key.export('base58btc'), key.did())

    // make message
    const dataObject = {
      prev: 'tid',
      patches: [
        ['put', ['path'], 'value'],
        ['del', ['path']],
      ],
      key: key.did(),
      sig: '',
    } as Diff
    const signed = await sign(dataObject, crypto) // replace sig with valid signature
    const msg = JSON.stringify(signed)

    // parse message
    const recv = JSON.parse(msg)
    if (recv.sig[0] !== 'z') {
      throw "signatures must be 'z'+ base58btc"
    }
    const recvSig = uint8arrays.fromString(recv.sig.slice(1), 'base58btc')
    recv.sig = ''
    const recvData = uint8arrays.fromString(JSON.stringify(recv))

    // validate signature
    const valid = await verifyDidSig(recv.key, recvData, recvSig)
    expect(valid).toBeTruthy()
  })

  it('sign validateSig', async () => {
    // pre baked signed diff
    if (accountCrypto === null) {
      return
    }
    
    expect(
      await validateSig({
        prev: '3j2b-pul-dlia-22',
        patches: [],
        key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
        sig: 'z5wYnrLa136SZsdxEvrbpLwu5wi6FDsynwiVeNR3KoJqVzgBUXLv9VQffLaz78w4tngKURh1cdbZ837S6PFC9Tu4y',
      } as Document, consortiumCrypto as Asymmetric),
    ).toBeTruthy()

    // fresh baked signed diff
    const diff = await sign(
      {
        prev: '3j2b-pul-dlia-22',
        patches: [],
        key: (await keyAccount).did(),
        sig: '',
      },
      accountCrypto,
    )
    // console.log(diff)
    expect(await validateSig(diff, consortiumCrypto as Asymmetric)).toBeTruthy()
  })

  it('tid next', async () => {
    const tic = TID.next().formatted()
    const toc = TID.next().formatted()
    // console.log(tic, toc)
    expect(toc > tic).toBeTruthy()
  })

  it('tickFromDiffs', async () => {
    if (consortiumCrypto === null) {
      return
    }

    const tick = await tickFromDiffs(
      {
        '3j55-hih-g24c-22': {
          a: 1,
          b: 2,
          c: 3,
          'adx/account_keys': [
            'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
          ],
        },
        '3j55-hiu-hcxs-22': {
          prev: '3j55-hih-g24c-22',
          patches: [['put', ['d'], 4]],
          key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
          sig: 'z58kG77wksPLi8185y6fsJG3NidUjYVBzBKVqSG3T5NQKwrNu9d6aL2UorPRzre4VCvKUASuec53jain2LRaMCtmZ',
        },
        '3j55-hk2-pbqk-22': {
          prev: '3j55-hiu-hcxs-22',
          patches: [['del', ['b']]],
          key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
          sig: 'z45gdspAmr9W1tC2KCBrnugdQSXP7fbTUvxz8yM1QnPPNLTKHs2PWzDYgmJe8RPLhZKrfpVFEsvaCMHkhLkFGfxRo',
        },
        '3j55-hki-vs6w-22': {
          prev: '3j55-hk2-pbqk-22',
          patches: [['put', ['e', 'ea'], 'each']],
          key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
          sig: 'z66WkmrsuVNiqBT3mhjF8G5MNcgpcKbCvXYinqFL73xYkwbSRvNNE7Mj8ak9gEN5FCkamWgsa82GrG984sJxcJdw8',
        },
        '3j55-hl6-3ctt-22': {
          prev: '3j55-hk2-pbqk-22',
          patches: [['put', ["Don't", 'put', 'me'], 'in']],
          key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
          sig: 'z5oHy2qCSKR9Z9hXuha6c7qEpUWMzGNeZcj8D5kDAxsWP6P8FN4kmSWHcoLv4q5umiyMWcUk5CePGeh51khRGEgGL',
        },
      },
      TID.next().formatted(),
      consortiumCrypto,
    )
    expect(
      await validateSig({
        tid: '3j57-dxc-6tjt-2o',
        diffs: {
          '3j55-hih-g24c-22': { a: 1, b: 2, c: 3 },
          '3j55-hiu-hcxs-22': {
            prev: '3j55-hih-g24c-22',
            patches: [['put', ['d'], 4]],
            key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
            sig: 'z58kG77wksPLi8185y6fsJG3NidUjYVBzBKVqSG3T5NQKwrNu9d6aL2UorPRzre4VCvKUASuec53jain2LRaMCtmZ',
          },
          '3j55-hk2-pbqk-22': {
            prev: '3j55-hiu-hcxs-22',
            patches: [['del', ['b']]],
            key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
            sig: 'z45gdspAmr9W1tC2KCBrnugdQSXP7fbTUvxz8yM1QnPPNLTKHs2PWzDYgmJe8RPLhZKrfpVFEsvaCMHkhLkFGfxRo',
          },
          '3j55-hki-vs6w-22': {
            prev: '3j55-hk2-pbqk-22',
            patches: [['put', ['e', 'ea'], 'each']],
            key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
            sig: 'z66WkmrsuVNiqBT3mhjF8G5MNcgpcKbCvXYinqFL73xYkwbSRvNNE7Mj8ak9gEN5FCkamWgsa82GrG984sJxcJdw8',
          },
          '3j55-hl6-3ctt-22': {
            prev: '3j55-hk2-pbqk-22',
            patches: [['put', ["Don't", 'put', 'me'], 'in']],
            key: 'did:key:zDnaeYgdnK7nVH2xNQENrBRJbdCQ1KKjxt5sbykiUGLAh46Ez',
            sig: 'z5oHy2qCSKR9Z9hXuha6c7qEpUWMzGNeZcj8D5kDAxsWP6P8FN4kmSWHcoLv4q5umiyMWcUk5CePGeh51khRGEgGL',
          },
        },
        id: 'did:aic:zwulnkrxrjkobowd',
        key: 'did:key:zDnaesnjCLbxSB2EiJgTZUYCBqHTkuDJDdLbSmaAn2bpqXtuY',
        sig: 'zE3zimBwrcerAfSATbhXjyMSaiGfmgP7BBaeCJKpFocTaj2fHiVnCbWYksb9czgRk4zEwPZ7RXvYEXmqVeiyoUNu',
      }, consortiumCrypto as Asymmetric),
    ).toBeTruthy()
    expect(await validateSig(JSON.parse(JSON.stringify(tick)), consortiumCrypto as Asymmetric)).toBeTruthy()
  })

  it('should updateTick', async () => {
    if (consortiumCrypto === null) {
      return
    }
    if (accountCrypto === null) {
      return
    }

    const doc = {
      'adx/account_keys': [
        'did:key:zDnaeycJUNQugcrag1WmLePtK9agLYLyXvscnQM4FHm1ASiRV',
      ],
      'adx/recovery_keys':[
        'did:key:zDnaeYHbbWiaCwAXvHXRyVqENDv8Sr3fwHW8P5eakkz4MqsTa',
      ],
    }
    const didOfDoc = "did:aic:zrr5lxhs4rjlowv5"
    if (didOfDoc !== `did:aic:${await pid(doc)}`) {
      console.log('pid', await pid(doc))
    }
    const tick1 = await updateTick(
      didOfDoc, 
      TID.next().formatted(), 
      doc,
      null,
      consortiumCrypto
    )
    if ('error' in tick1){
      console.log(tick1)
      expect(false).toBeTruthy()
      return
    }
    // console.log('tick1', tick1, await tickToDidDoc(tick1, (await keyConsortium).did(), consortiumCrypto as Asymmetric))

    expect(await validateSig(tick1, consortiumCrypto as Asymmetric)).toBeTruthy()
    expect(tick1.did).toEqual(didOfDoc)
    expect(tick1.key).toEqual('did:key:zDnaeeL44gSLMViH9khhTbngNd9r72MhUPo4WKPeSfB8xiDTh')
    
    const tids1 = Object.keys(tick1.diffs).sort()
    const tick2 = await updateTick(
      didOfDoc, 
      TID.next().formatted(),
      await sign(
        // candidateDiff is singed on clint then sent to consortium
        {
          prev: tids1.at(-1),
          patches: [
            ['put', ['name'], 'aaron.blueskyweb.xyz'],
          ],
          key: (await keyAccount).did(),
          sig: ''
        },
        (await accountCrypto), // only the client has this key
      ),
      tick1,
      (await consortiumCrypto) // only the consortium has this key
    )
    if ('error' in tick2){
      console.log(tick2)
      expect(false).toBeTruthy()
      return
    }
    // console.log('tick2', tick2, await tickToDidDoc(tick2, (await keyConsortium).did(), consortiumCrypto as Asymmetric))

    expect(await validateSig(tick2, consortiumCrypto as Asymmetric)).toBeTruthy()
    expect(tick1.did).toEqual(didOfDoc)
    expect(tick1.key).toEqual('did:key:zDnaeeL44gSLMViH9khhTbngNd9r72MhUPo4WKPeSfB8xiDTh')


    const tids2 = Object.keys(tick2.diffs).sort()
    const tick3 = await updateTick(
      didOfDoc,
      TID.next().formatted(),
      await sign(
        {
          prev: tids2.at(-1),
          patches: [
            ['del', ['adx/account_keys']],
          ],
          key: (await keyAccount).did(),
          sig: ''
        },
        accountCrypto,
      ),
      tick2,
      consortiumCrypto
    )
    if ('error' in tick3){
      console.log(tick3)
      expect(false).toBeTruthy()
      return
    }
    // console.log('tick3', JSON.stringify(tick3), await tickToDidDoc(tick3, (await keyConsortium).did(), consortiumCrypto as Asymmetric))
    expect(await validateSig(tick3, consortiumCrypto as Asymmetric)).toBeTruthy()
    expect(tick3.did).toEqual(didOfDoc)
    expect(tick3.key).toEqual('did:key:zDnaeeL44gSLMViH9khhTbngNd9r72MhUPo4WKPeSfB8xiDTh')

    const tids3 = Object.keys(tick3.diffs).sort()
    const tick4 = await updateTick(
      didOfDoc,
      TID.next().formatted(),
      await sign(
        {
          prev: tids3.at(-1),
          patches: [
            ['put', ['hello'], 'world'],
          ],
          key: (await keyAccount).did(),
          sig: ''
        },
        (await accountCrypto),
      ),
      tick3,
      (await consortiumCrypto)
    )
    if ('error' in tick4){
      console.log(tick4)
      expect(false).toBeTruthy()
      return
    }
    // console.log('tick4', JSON.stringify(tick4), await tickToDidDoc(tick4, (await keyConsortium).did(), consortiumCrypto as Asymmetric))
    expect(await validateSig(tick4, consortiumCrypto as Asymmetric)).toBeTruthy()
    expect(tick4.did).toEqual(didOfDoc)
    expect(tick4.key).toEqual('did:key:zDnaeeL44gSLMViH9khhTbngNd9r72MhUPo4WKPeSfB8xiDTh')
  })
})
