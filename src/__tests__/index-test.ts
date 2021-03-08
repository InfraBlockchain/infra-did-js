import InfraDID from '../index'
import { Resolver } from 'did-resolver'
import { getResolver } from "infra-did-resolver"

describe('InfraDID', () => {

  // const networkId = 'local'
  // const registryContract ='infradidregi'
  // const rpcEndpoint = 'http://127.0.0.1:8888'

  // const txfeePayerAccount = 'infradidinit'
  // const txfeePayerPrivateKey = '5HwviX14H6M2g4qgF8DU1CSWtxZqx2c5bDZQJBmQmgzCTyEoJtU' // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db

  const networkId = 'vapptest1'
  const registryContract = 'fmapkumrotfc'
  const rpcEndpoint = 'https://api.testnet.eos.io'

  const txfeePayerAccount = 'qwexfhmvvdci'
  const txfeePayerPrivateKey = '5KV84hXSJvu3nfqb9b1raRMnzvULaHH6Fsaz4xBZG2QbfPwMg76' // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db

  const confDefaults = {
    networkId,
    registryContract,
    rpcEndpoint,
    // jwtSigner?: any,
    txfeePayerAccount,
    txfeePayerPrivateKey,
  }

  const infraDidResolverConfig = {
    networks : [
      {
        networkId,
        registryContract,
        rpcEndpoint: 'https://api.testnet.eos.io'
      }
    ]
  }

  let infraDidResolver, didResolver

  beforeAll(async () => {
    infraDidResolver = getResolver(infraDidResolverConfig)
    didResolver = new Resolver(infraDidResolver)
  })

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
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx`, //pubKeyDID.did,
        didOwnerPrivateKey: 'PVT_K1_2anMa3Wq7rkQy7AyNdqMDmkycT6emGnP857zmZa13FyhkHY9JD', //pubKeyDID.privateKey,
      }

      const didApi = new InfraDID(conf)
      const resSetAttr = await didApi.setAttributePubKeyDID('svc/MessagingService', 'https://infradid.com/pk/3/mysvcr4')
      console.log({resSetAttr})

      expect(resSetAttr.transaction_id).toBeDefined()
      // expect(didApi.setAttribute('svc/MessagingService', 'https://infradid.com/pk/3/mysvcr3')).resolves.toBe({})

    })

    it('should remove pubkey DID attribute',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc`,
        didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ',
        // did: `did:infra:${networkId}:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx`, //pubKeyDID.did,
        // didOwnerPrivateKey: 'PVT_K1_2anMa3Wq7rkQy7AyNdqMDmkycT6emGnP857zmZa13FyhkHY9JD', //pubKeyDID.privateKey,
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
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc`,
        didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ',
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
        did: `did:infra:${networkId}:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc`,
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

    it('should clear pubkey DID chain db rows',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx`,
        didOwnerPrivateKey: 'PVT_K1_2anMa3Wq7rkQy7AyNdqMDmkycT6emGnP857zmZa13FyhkHY9JD',
      }

      const didApi = new InfraDID(conf)
      const resRevoke = await didApi.clearPubKeyDID()
      console.log({resRevoke})

      expect(resRevoke.transaction_id).toBeDefined()
    })
  })

  describe('Account-based DID', () => {
    it('should set account DID attribute',async () => {
      // const pubKeyDID = InfraDID.createPubKeyDIDsecp256k1(networkId)
      // console.log({pubKeyDID})

      // const account = 'diduser22222'
      // const accountPrivateKey = 'PVT_K1_2uTgvsmdT7U12HNqLg1Y8UQtAtgoDew2erCkNuPvqDMzcUspCS'

      const account = 'jghpykcpaoko'
      const accountPrivateKey = '5Hucf4g3riLDHVWKbLLbnQU2cqC5oAXoP6XiPjYGc4qS1ASqq5T'

      const conf = {
        did: `did:infra:${networkId}:${account}`,
        didOwnerPrivateKey: accountPrivateKey,
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

  describe('Sign and verify JWT', () => {
    it('should sign and verify JWT (Verifiable Credential)',async () => {
      const signerDidConf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx`, //pubKeyDID.did,
        didOwnerPrivateKey: 'PVT_K1_2anMa3Wq7rkQy7AyNdqMDmkycT6emGnP857zmZa13FyhkHY9JD', //pubKeyDID.privateKey,
        // didOwnerPrivateKey: 'PVT_K1_2YiPos21thxcTSrYLafUrvnHHLUkZKVxTdUdysJGAfjAAbZqNe'
      }

      const verifierDidConf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr`, //pubKeyDID.did,
        didOwnerPrivateKey: 'PVT_K1_22gQdGw4JPaHs3E9kkwKZ2mW9WR1YE6XnyDN6juTSaet7ecSGN', //pubKeyDID.privateKey,
      }

      const audienceDid = verifierDidConf.did

      const signerDidApi = new InfraDID(signerDidConf)
      const payload = {
        aud: audienceDid,
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          credentialSubject: {
            id: signerDidConf.did,
            claim1: 'claim1_value',
            claim2: 'claim2_value'
          }
        }
      }
      const jwt = await signerDidApi.signJWT(payload)
      console.log({jwt})

      const verifierDidApi = new InfraDID(verifierDidConf)
      const resVerify = await verifierDidApi.verifyJWT(jwt, didResolver, audienceDid)

      console.dir(resVerify, { depth: null })
      expect(resVerify.payload.aud === audienceDid).toBeTruthy()
      expect(resVerify.payload.vc.credentialSubject.claim1 === payload.vc.credentialSubject.claim1).toBeTruthy()
      expect(resVerify.payload.vc.credentialSubject.claim2 === payload.vc.credentialSubject.claim2).toBeTruthy()
      expect(resVerify.payload.iss === signerDidConf.did).toBeTruthy()
      expect(resVerify.issuer === signerDidConf.did).toBeTruthy()
      expect(resVerify.jwt === jwt).toBeTruthy()

    })
  })


})
