import InfraDID from '../index'

describe('InfraDID', () => {

  const networkId = 'local'
  const registryContract ='infradidregi'
  const rpcEndpoint = 'http://127.0.0.1:8888'

  const txfeePayerAccount = 'infradidinit'
  const txfeePayerPrivateKey = '5HwviX14H6M2g4qgF8DU1CSWtxZqx2c5bDZQJBmQmgzCTyEoJtU' // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db


  describe('DID creation', () => {
    it('should create pubKey DID (secp256k1)', () => {
      const pubKeyDID = InfraDID.createPubKeyDIDsecp256k1(networkId)
      console.log({pubKeyDID})

      expect(pubKeyDID).toBeDefined()
      expect(pubKeyDID.did.startsWith(`did:infra:${networkId}:${pubKeyDID.publicKey}`)).toBeTruthy()
      expect(pubKeyDID.publicKey.startsWith('PUB_K1_')).toBeTruthy()
      expect(pubKeyDID.privateKey.startsWith('PVT_K1_')).toBeTruthy()
    })
  })

  describe('Public-Key-based DID', () => {
    it('should set pubkey DID attribute',async () => {
      // const pubKeyDID = InfraDID.createPubKeyDIDsecp256k1(networkId)
      // console.log({pubKeyDID})

      const conf = {
        did: 'did:infra:local:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc', //pubKeyDID.did,
        didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ', //pubKeyDID.privateKey,
        networkId,
        registryContract,
        rpcEndpoint,
        // jwtSigner?: any,
        txfeePayerAccount,
        txfeePayerPrivateKey,
      }

      const didApi = new InfraDID(conf)
      const resSetAttr = await didApi.setAttributePubKeyDID('svc/MessagingService', 'https://infradid.com/pk/3/mysvcr4')
      console.log({resSetAttr})

      expect(resSetAttr.transaction_id).toBeDefined()
      // expect(didApi.setAttribute('svc/MessagingService', 'https://infradid.com/pk/3/mysvcr3')).resolves.toBe({})

    })

    it('should remove pubkey DID attribute',async () => {
      const conf = {
        did: 'did:infra:local:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc',
        didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ',
        networkId,
        registryContract,
        rpcEndpoint,
        // jwtSigner?: any,
        txfeePayerAccount,
        txfeePayerPrivateKey,
      }

      const didApi = new InfraDID(conf)
      const resSetAttr = await didApi.setAttributePubKeyDID('svc/MessagingService', '')
      // const resSetAttr = await didApi.setAttributePubKeyDID('svc01', '')
      console.log({resSetAttr})

      expect(resSetAttr.transaction_id).toBeDefined()
    })

    it('should change pubkey DID owner key',async () => {

      // did: 'did:infra:local:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc',
      // didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ',

      const conf = {
        did: 'did:infra:local:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc',
        didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ',
        networkId,
        registryContract,
        rpcEndpoint,
        // jwtSigner?: any,
        txfeePayerAccount,
        txfeePayerPrivateKey,
      }

      // pubKeyDID: {
      //   did: 'did:infra:local:PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt',
      //     publicKey: 'PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt',
      //     privateKey: 'PVT_K1_2YiPos21thxcTSrYLafUrvnHHLUkZKVxTdUdysJGAfjAAbZqNe'
      // }

      const didApi = new InfraDID(conf)
      const resChangeOwner = await didApi.changeOwnerPubKeyDID('PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt')
      console.log({resChangeOwner})

      expect(resChangeOwner.transaction_id).toBeDefined()
    })

    it('should revoke pubkey DID',async () => {
      const conf = {
        did: 'did:infra:local:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc',
        // didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ',
        didOwnerPrivateKey: 'PVT_K1_2YiPos21thxcTSrYLafUrvnHHLUkZKVxTdUdysJGAfjAAbZqNe',
        networkId,
        registryContract,
        rpcEndpoint,
        // jwtSigner?: any,
        txfeePayerAccount,
        txfeePayerPrivateKey,
      }

      const didApi = new InfraDID(conf)
      const resRevoke = await didApi.revokePubKeyDID()
      console.log({resRevoke})

      expect(resRevoke.transaction_id).toBeDefined()
    })

  })

  describe('Account-based DID', () => {
    it('should set account DID attribute',async () => {
      // const pubKeyDID = InfraDID.createPubKeyDIDsecp256k1(networkId)
      // console.log({pubKeyDID})

      const conf = {
        did: 'did:infra:local:diduser22222',
        didOwnerPrivateKey: 'PVT_K1_2uTgvsmdT7U12HNqLg1Y8UQtAtgoDew2erCkNuPvqDMzcUspCS',
        networkId,
        registryContract,
        rpcEndpoint,
        // jwtSigner?: any,
        // txfeePayerAccount,
        // txfeePayerPrivateKey,
      }

      const didApi = new InfraDID(conf)
      const resSetAttr = await didApi.setAttributeAccountDID('svc/MessagingService', 'https://infradid.com/acc/1/mysvcr5')
      console.log({resSetAttr})

      expect(resSetAttr.transaction_id).toBeDefined()
    })
  })
})
