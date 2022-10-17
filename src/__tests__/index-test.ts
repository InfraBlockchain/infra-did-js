import InfraDID from '../index'
import { Resolver } from 'did-resolver'
// @ts-ignore
import { getResolver } from 'infra-did-resolver'
import {
  createVerifiableCredentialJwt,
  verifyCredential,
  createVerifiablePresentationJwt,
  verifyPresentation,
  CredentialPayload,
  PresentationPayload,
  VerifiableCredential
} from 'did-jwt-vc'

describe('InfraDID', () => {

  // const networkId = 'local'
  // const registryContract ='infradidregi'
  // const rpcEndpoint = 'http://127.0.0.1:8888'

  // const txfeePayerAccount = 'infradidinit'
  // const txfeePayerPrivateKey = '5HwviX14H6M2g4qgF8DU1CSWtxZqx2c5bDZQJBmQmgzCTyEoJtU' // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db

  // // const networkId = 'vapptest1'
  // const networkId = '01'
  // const registryContract = 'fmapkumrotfc'
  // const rpcEndpoint = 'https://api.testnet.eos.io'

  const networkId = '01'
  // const registryContract ='infradidregi'
  // const rpcEndpoint = 'http://kdca.osong.bc.coov.io:9180'
  // // const rpcEndpoint = 'http://152.99.73.160:9180'
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
        rpcEndpoint
      }
    ]
  }

  let infraDidResolver, didResolver

  beforeAll(async () => {
    infraDidResolver = getResolver(infraDidResolverConfig)
    didResolver = new Resolver({...infraDidResolver})
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
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`, //pubKeyDID.did,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', //pubKeyDID.privateKey,
      }

      const didApi = new InfraDID(conf)
      const resSetAttr: any = await didApi.setAttributePubKeyDID('svc/MessagingService', 'https://infradid.com/pk/3/mysvcr9')
      console.log({resSetAttr})

      expect(resSetAttr.transaction_id).toBeDefined()
      // expect(didApi.setAttribute('svc/MessagingService', 'https://infradid.com/pk/3/mysvcr3')).resolves.toBe({})

    })

    it('should remove pubkey DID attribute',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`, //pubKeyDID.did,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', //pubKeyDID.privateKey,
        // did: `did:infra:${networkId}:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx`, //pubKeyDID.did,
        // didOwnerPrivateKey: 'PVT_K1_2anMa3Wq7rkQy7AyNdqMDmkycT6emGnP857zmZa13FyhkHY9JD', //pubKeyDID.privateKey,
      }

      const didApi = new InfraDID(conf)
      const resSetAttr: any = await didApi.setAttributePubKeyDID('svc/MessagingService', '')
      // const resSetAttr = await didApi.setAttributePubKeyDID('svc01', '')
      console.log({resSetAttr})

      expect(resSetAttr.transaction_id).toBeDefined()
    })

    it('should change pubkey DID owner key',async () => {

      // did: 'did:infra:local:PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc',
      // didOwnerPrivateKey: 'PVT_K1_2Gowe7JiuzsxifyjKoQ2XNzXe1FcTax6vsGhU58Kxt4LuLFDyQ',

      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`,
        didOwnerPrivateKey: 'PVT_K1_2QUHdXAKxtfbCbFDL5FoVtLpPp6sWQpXzRpW7dXXZFS2qVqFFn',
      }

      // pubKeyDID: {
      //   did: 'did:infra:local:PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt',
      //     publicKey: 'PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt',
      //     privateKey: 'PVT_K1_2YiPos21thxcTSrYLafUrvnHHLUkZKVxTdUdysJGAfjAAbZqNe'
      // }

      const didApi = new InfraDID(conf)
      const resChangeOwner: any = await didApi.changeOwnerPubKeyDID('PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt')
      console.log({resChangeOwner})

      expect(resChangeOwner.transaction_id).toBeDefined()
    })

    it('should revoke pubkey DID',async () => {
      const conf = {
        did: `did:infra:${networkId}:PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt`,
        didOwnerPrivateKey: 'PVT_K1_2YiPos21thxcTSrYLafUrvnHHLUkZKVxTdUdysJGAfjAAbZqNe',
        networkId,
        registryContract,
        rpcEndpoint,
        // jwtSigner?: any,
        txfeePayerAccount,
        txfeePayerPrivateKey,
      }

      const didApi = new InfraDID(conf)
      const resRevoke: any = await didApi.revokePubKeyDID()
      console.log({resRevoke})

      expect(resRevoke.transaction_id).toBeDefined()
    })

    it('should clear pubkey DID chain db rows',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', 
      }

      const didApi = new InfraDID(conf)
      const resClear: any = await didApi.clearPubKeyDID()
      console.log({resClear})

      expect(resClear.transaction_id).toBeDefined()
    })

    it('should register pubkey DID as trusted DID',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', 
      }

      const didApi = new InfraDID(conf)
      const resAdd: any = await didApi.registerTrustedPubKeyDID(txfeePayerAccount, "PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU", JSON.stringify({type:"issuer"}))
      console.log({resAdd})

      expect(resAdd.transaction_id).toBeDefined()
    })

    it('should update trusted pubkey DID properties',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', 
      }

      const didApi = new InfraDID(conf)
      const resUpdate: any = await didApi.updateTrustedPubKeyDID(txfeePayerAccount, "PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU", JSON.stringify({type:"verifier"}))
      console.log({resUpdate})

      expect(resUpdate.transaction_id).toBeDefined()
    })

    it('should get trusted pubkey DID',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', 
      }

      const didApi = new InfraDID(conf)
      const resGet: any = await didApi.getTrustedPubKeyDID();
      console.log({resGet})

      expect(resGet).toBeDefined();
    })

    it('should get trusted pubkey DID By Trusted',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', 
      }

      const didApi = new InfraDID(conf)
      const resGet: any = await didApi.getTrustedPubKeyDIDByTrusted(txfeePayerAccount);
      console.log({resGet})

      expect(resGet).toBeDefined();
    })

    it('should get trusted pubkey DID By Target',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', 
      }

      const didApi = new InfraDID(conf)
      const resGet: any = await didApi.getTrustedPubKeyDIDByTarget("PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU");
      console.log({resGet})

      expect(resGet).toBeDefined();
    })

    it('should remove trusted pubkey DID',async () => {
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', 
      }

      const didApi = new InfraDID(conf)
      const resRemove: any = await didApi.removeTrustedPubKeyDID(txfeePayerAccount, "PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU");
      console.log({resRemove})

      expect(resRemove.transaction_id).toBeDefined()
    })
  })

  describe('Account-based DID', () => {

    const account = 'jghpykcpaoko'
    const accountPrivateKey = '5Hucf4g3riLDHVWKbLLbnQU2cqC5oAXoP6XiPjYGc4qS1ASqq5T'
    
    it('should set account DID attribute',async () => {
      // const pubKeyDID = InfraDID.createPubKeyDIDsecp256k1(networkId)
      // console.log({pubKeyDID})

      // const account = 'diduser22222'
      // const accountPrivateKey = 'PVT_K1_2uTgvsmdT7U12HNqLg1Y8UQtAtgoDew2erCkNuPvqDMzcUspCS'
      
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
      const resSetAttr: any = await didApi.setAttributeAccountDID('svc/MessagingService', 'https://infradid.com/acc/1/mysvcr7')
      console.log({resSetAttr})

      expect(resSetAttr.transaction_id).toBeDefined()
    })

    it('should register account DID as trusted DID',async () => {
      const conf = {
        did: `did:infra:${networkId}:${account}`,
        didOwnerPrivateKey: accountPrivateKey,
        networkId,
        registryContract,
        rpcEndpoint,
      }

      const didApi = new InfraDID(conf)
      const resAdd: any = await didApi.registerTrustedAccountDID(txfeePayerAccount, conf.did.split(":")[3], JSON.stringify({type:"issuer"}))
      console.log({resAdd})

      expect(resAdd.transaction_id).toBeDefined()
    })

    it('should update account pubkey DID properties',async () => {
      const conf = {
        did: `did:infra:${networkId}:${account}`,
        didOwnerPrivateKey: accountPrivateKey,
        networkId,
        registryContract,
        rpcEndpoint,
      }

      const didApi = new InfraDID(conf)
      const resUpdate: any = await didApi.updateTrustedAccountDID(txfeePayerAccount, conf.did.split(":")[3], JSON.stringify({type:"verifier"}))
      console.log({resUpdate})

      expect(resUpdate.transaction_id).toBeDefined()
    })

    it('should get account pubkey DID',async () => {
      const conf = {
        did: `did:infra:${networkId}:${account}`,
        didOwnerPrivateKey: accountPrivateKey,
        networkId,
        registryContract,
        rpcEndpoint,
      }

      const didApi = new InfraDID(conf)
      const resGet: any = await didApi.getTrustedAccountDID();
      console.log({resGet})

      expect(resGet).toBeDefined();
    })

    it('should get account pubkey DID By Trusted',async () => {
      const conf = {
        did: `did:infra:${networkId}:${account}`,
        didOwnerPrivateKey: accountPrivateKey,
        networkId,
        registryContract,
        rpcEndpoint,
      }

      const didApi = new InfraDID(conf)
      const resGet: any = await didApi.getTrustedAccountDIDByTrusted(txfeePayerAccount);
      console.log({resGet})

      expect(resGet).toBeDefined();
    })

    it('should get account pubkey DID By Target',async () => {
      const conf = {
        did: `did:infra:${networkId}:${account}`,
        didOwnerPrivateKey: accountPrivateKey,
        networkId,
        registryContract,
        rpcEndpoint,
      }

      const didApi = new InfraDID(conf)
      const resGet: any = await didApi.getTrustedAccountDIDByTarget(conf.did.split(":")[3]);
      console.log({resGet})

      expect(resGet).toBeDefined();
    })

    it('should remove account pubkey DID',async () => {
      const conf = {
        did: `did:infra:${networkId}:${account}`,
        didOwnerPrivateKey: accountPrivateKey,
        networkId,
        registryContract,
        rpcEndpoint,
      }

      const didApi = new InfraDID(conf)
      const resRemove: any = await didApi.removeTrustedAccountDID(txfeePayerAccount, conf.did.split(":")[3]);
      console.log({resRemove})

      expect(resRemove.transaction_id).toBeDefined()
    })
  })

  describe('Sign and verify JWT', () => {
    it('should sign and verify JWT (Verifiable Credential)',async () => {
      const signerDidConf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`, //pubKeyDID.did,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', //pubKeyDID.privateKey,
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

      const didDoc = await didResolver.resolve(signerDidConf.did)
      console.dir(didDoc, { depth:null })

      console.dir(resVerify, { depth: null })
      expect(resVerify.payload.aud === audienceDid).toBeTruthy()
      expect(resVerify.payload.vc.credentialSubject.claim1 === payload.vc.credentialSubject.claim1).toBeTruthy()
      expect(resVerify.payload.vc.credentialSubject.claim2 === payload.vc.credentialSubject.claim2).toBeTruthy()
      expect(resVerify.payload.iss === signerDidConf.did).toBeTruthy()
      expect(resVerify.issuer === signerDidConf.did).toBeTruthy()
      expect(resVerify.jwt === jwt).toBeTruthy()

    })
  })

  describe('did-jwt-vc interoperability test', () => {
    it('Create and Verify Verifiable Credential Jwt',async () => {
      const vcIssuerDidConf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
        didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA',
      }

      const vcSubjectDid = `did:infra:${networkId}:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt`

      const issuerDidApi = new InfraDID(vcIssuerDidConf)
      const issuer = issuerDidApi.getJwtVcIssuer()
      const credential : CredentialPayload = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: 'http://example.vc/credentials/123532',
        type: ['VerifiableCredential', 'VaccinationCredential'],
        issuer: vcIssuerDidConf.did,
        // issuanceDate: '2021-03-17T12:17:26.000Z',
        issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
        credentialSubject: {
          id: vcSubjectDid,
          claim1: 'claim1_value',
          claim2: 'claim2_value'
        }
      }
      console.log(new Date(credential.issuanceDate).valueOf())
      const vcJWT = await createVerifiableCredentialJwt(credential, issuer)
      console.log({vcJWT})

      const verifiedCredential: any = await verifyCredential(vcJWT, didResolver)
      console.log(JSON.stringify(verifiedCredential, null, 3))

      expect(verifiedCredential.payload.vc.credentialSubject.claim1).toBe('claim1_value')
      expect(verifiedCredential.payload.vc.credentialSubject.claim2).toBe('claim2_value')
      expect(verifiedCredential.payload.sub).toBe(vcSubjectDid)
      expect(verifiedCredential.payload.jti).toBe(credential.id)
      expect(verifiedCredential.payload.nbf).toBe(Math.floor(new Date(credential.issuanceDate).getTime()/1000))
      expect(verifiedCredential.payload.iss).toBe(vcIssuerDidConf.did)
      expect(verifiedCredential.didResolutionResult.didDocument.id).toBe(vcIssuerDidConf.did)
      expect(verifiedCredential.issuer).toBe(vcIssuerDidConf.did)
      // @ts-ignore
      expect(verifiedCredential.signer.id.startsWith(vcIssuerDidConf.did)).toBeTruthy()
      expect(verifiedCredential.jwt).toBe(vcJWT)
      expect(verifiedCredential.verifiableCredential.credentialSubject.claim1).toBe('claim1_value')
      expect(verifiedCredential.verifiableCredential.credentialSubject.claim2).toBe('claim2_value')
      expect(verifiedCredential.verifiableCredential.credentialSubject.id).toBe(vcSubjectDid)
      expect(verifiedCredential.verifiableCredential.issuer.id).toBe(vcIssuerDidConf.did)
      // expect(verifiedCredential.verifiableCredential.issuanceDate).toBe(credential.issuanceDate)
      expect(verifiedCredential.verifiableCredential.proof.jwt).toBe(vcJWT)

    /*
    {
       "payload": {
          "vc": {
             "credentialSubject": {
                "claim1": "claim1_value",
                "claim2": "claim2_value"
             },
             "@context": [
                "https://www.w3.org/2018/credentials/v1"
             ],
             "type": [
                "VerifiableCredential",
                "VaccinationCredential"
             ]
          },
          "sub": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
          "jti": "http://example.vc/credentials/123532",
          "nbf": 1615988953,
          "iss": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU"
       },
       "didResolutionResult": {
          "didResolutionMetadata": {
             "contentType": "application/did+ld+json"
          },
          "didDocument": {
             "@context": "https://www.w3.org/ns/did/v1",
             "id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
             "verificationMethod": [
                {
                   "id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU#controller",
                   "type": "EcdsaSecp256k1VerificationKey2019",
                   "controller": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
                   "publicKeyHex": "03cdf359def0d227223b10fba97c3b786899c0cc33ffd6cc8d60ce709f489c4f47"
                }
             ],
             "authentication": [
                "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU#controller"
             ],
             "service": [
                {
                   "id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU#service-1",
                   "type": "MessagingService",
                   "serviceEndpoint": "https://infradid.com/pk/3/mysvcr9"
                }
             ]
          },
          "didDocumentMetadata": {}
       },
       "issuer": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
       "signer": {
          "id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU#controller",
          "type": "EcdsaSecp256k1VerificationKey2019",
          "controller": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
          "publicKeyHex": "03cdf359def0d227223b10fba97c3b786899c0cc33ffd6cc8d60ce709f489c4f47"
       },
       "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNTk4ODk1MywiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.6nOFkY4PT4Dj9UTrDtWQCbP9Pv-cXFqv67Bq2ZFPBiRecpRB17Yhq7S9gLVAoZwocCqEzJqOM1uXheZNKC5KTA",
       "verifiableCredential": {
          "credentialSubject": {
             "claim1": "claim1_value",
             "claim2": "claim2_value",
             "id": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt"
          },
          "issuer": {
             "id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU"
          },
          "id": "http://example.vc/credentials/123532",
          "type": [
             "VerifiableCredential",
             "VaccinationCredential"
          ],
          "@context": [
             "https://www.w3.org/2018/credentials/v1"
          ],
          "issuanceDate": "2021-03-17T13:49:13.000Z",
          "proof": {
             "type": "JwtProof2020",
             "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNTk4ODk1MywiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.6nOFkY4PT4Dj9UTrDtWQCbP9Pv-cXFqv67Bq2ZFPBiRecpRB17Yhq7S9gLVAoZwocCqEzJqOM1uXheZNKC5KTA"
          }
       }
    }
    */
    })

    it('Create and Verify Verifiable Presentation Jwt',async () => {
      const vcHolderDidConf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt`,
        didOwnerPrivateKey: 'PVT_K1_2NqB8nrfnd6Eqj46uQvvKXiwNj6rp7dp3iJjm4K86BJW4KGSVb',
      }

      const verifierDid = `did:infra:${networkId}:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`

      const vcJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNTk4NzExNywiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.tGSAsEbF4bKb5bEWNtU1nItaMTYraSstaD2cxSfk9K13KZDOU07O3c6-2u9QKWpxHAm0ZhDGq9QQ07XDeGoqmw'
      const vcJson: VerifiableCredential = {
        '@context': [
          "https://www.w3.org/2018/credentials/v1"
        ],
        id: 'http://example.vc/credentials/123532',
        type: [
          'VerifiableCredential',
          'VaccinationCredential'
        ],
        issuer: {
          id: 'did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU'
        },
        issuanceDate: '2021-03-17T13:18:37.000Z',
        credentialSubject: {
          id: 'did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt',
          claim1: 'claim1_value',
          claim2: 'claim2_value'
        },
        proof: {
          type: 'JwtProof2020',
          jwt: vcJWT
        }
      }

      const presentation : PresentationPayload = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: 'VerifiablePresentation',
        verifiableCredential: [ vcJWT /*vcJson*/ ],
        holder: vcHolderDidConf.did,
        verifier: verifierDid,
        issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
        expirationDate: new Date(new Date().getTime() + 10*60*1000).toISOString()
      }

      const holderDidApi = new InfraDID(vcHolderDidConf)
      const holder = holderDidApi.getJwtVcIssuer()

      const vpJWT = await createVerifiablePresentationJwt(presentation, holder)
      console.log({vpJWT})

      const verifiedPresentation: any = await verifyPresentation(vpJWT, didResolver, { audience: verifierDid })
      console.log(JSON.stringify(verifiedPresentation, null, 3))

      expect(verifiedPresentation.payload.iss).toBe(vcHolderDidConf.did)
      expect(verifiedPresentation.payload.aud[0]).toBe(verifierDid)
      expect(verifiedPresentation.didResolutionResult.didDocument.id).toBe(vcHolderDidConf.did)
      expect(verifiedPresentation.issuer).toBe(vcHolderDidConf.did)
      expect(verifiedPresentation.jwt).toBe(vpJWT)
      expect(verifiedPresentation.verifiablePresentation.verifiableCredential[0].issuer.id).toBe(vcJson.issuer.id)
      expect(verifiedPresentation.verifiablePresentation.verifiableCredential[0].id).toBe(vcJson.id)
      expect(verifiedPresentation.verifiablePresentation.verifiableCredential[0].proof.jwt).toBe(vcJson.proof.jwt)
      expect(verifiedPresentation.verifiablePresentation.holder).toBe(vcHolderDidConf.did)
      expect(verifiedPresentation.verifiablePresentation.verifier[0]).toBe(verifierDid)
      expect(verifiedPresentation.verifiablePresentation.type[0]).toBe('VerifiablePresentation')
      expect(verifiedPresentation.verifiablePresentation.proof.jwt).toBe(vpJWT)

    /*
    verifiedPresentation = {
       "payload": {
          "exp": 1615988929,
          "vp": {
             "@context": [
                "https://www.w3.org/2018/credentials/v1"
             ],
             "type": [
                "VerifiablePresentation"
             ],
             "verifiableCredential": [
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNTk4NzExNywiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.tGSAsEbF4bKb5bEWNtU1nItaMTYraSstaD2cxSfk9K13KZDOU07O3c6-2u9QKWpxHAm0ZhDGq9QQ07XDeGoqmw"
             ]
          },
          "nbf": 1615988329,
          "iss": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
          "aud": [
             "did:infra:01:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz"
          ]
       },
       "didResolutionResult": {
          "didResolutionMetadata": {
             "contentType": "application/did+ld+json"
          },
          "didDocument": {
             "@context": "https://www.w3.org/ns/did/v1",
             "id": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
             "verificationMethod": [
                {
                   "id": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt#controller",
                   "type": "EcdsaSecp256k1VerificationKey2019",
                   "controller": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
                   "publicKeyHex": "0375fb59ca8c9b7e6b96ae2ba6396ab05ebb8bda53d55895278d482e9478c183e9"
                }
             ],
             "authentication": [
                "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt#controller"
             ]
          },
          "didDocumentMetadata": {}
       },
       "issuer": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
       "signer": {
          "id": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt#controller",
          "type": "EcdsaSecp256k1VerificationKey2019",
          "controller": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
          "publicKeyHex": "0375fb59ca8c9b7e6b96ae2ba6396ab05ebb8bda53d55895278d482e9478c183e9"
       },
       "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJleHAiOjE2MTU5ODg5MjksInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUoyWXlJNmV5SmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpqYkdGcGJURWlPaUpqYkdGcGJURmZkbUZzZFdVaUxDSmpiR0ZwYlRJaU9pSmpiR0ZwYlRKZmRtRnNkV1VpZlN3aVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbFpoWTJOcGJtRjBhVzl1UTNKbFpHVnVkR2xoYkNKZGZTd2ljM1ZpSWpvaVpHbGtPbWx1Wm5KaE9qQXhPbEJWUWw5TE1WODNha05FWVhKWWJsb3pVMlJRUVhkbVJrVmphVlJUZVZWNlFUUm1ibVp1YTNSMlJrZzVSbW8zU2pnNVZYSkdhVWh3ZENJc0ltcDBhU0k2SW1oMGRIQTZMeTlsZUdGdGNHeGxMblpqTDJOeVpXUmxiblJwWVd4ekx6RXlNelV6TWlJc0ltNWlaaUk2TVRZeE5UazROekV4Tnl3aWFYTnpJam9pWkdsa09tbHVabkpoT2pBeE9sQlZRbDlMTVY4NFVIZEhOMjltTlVJNGNEbE5jR0YzTmxoNlpYbFpkRk5YU25sbFUxaFdkSGhhYUZCSVVVTTFaVnA0V2tOcmNXbE1WU0o5LnRHU0FzRWJGNGJLYjViRVdOdFUxbkl0YU1UWXJhU3N0YUQyY3hTZms5SzEzS1pET1UwN08zYzYtMnU5UUtXcHhIQW0wWmhER3E5UVEwN1hEZUdvcW13Il19LCJuYmYiOjE2MTU5ODgzMjksImlzcyI6ImRpZDppbmZyYTowMTpQVUJfSzFfN2pDRGFyWG5aM1NkUEF3ZkZFY2lUU3lVekE0Zm5mbmt0dkZIOUZqN0o4OVVyRmlIcHQiLCJhdWQiOlsiZGlkOmluZnJhOjAxOlBVQl9LMV81VGFFZ3BWdXIzOTFkaW1WbkZDREhCMTIyRFhZQmJ3V2RLVXBFSkNOdjNrbzFLTVl3eiJdfQ.ud6HTb2dI4d6epdKdmSl4gZXxJ_XDzRvmjIwRTeBUHxb-dHLWFPFYdA__t4OQgHV48ei9TSgP93Hs8f5GU_q8w",
       "verifiablePresentation": {
          "verifiableCredential": [
             {
                "credentialSubject": {
                   "claim1": "claim1_value",
                   "claim2": "claim2_value",
                   "id": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt"
                },
                "issuer": {
                   "id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU"
                },
                "id": "http://example.vc/credentials/123532",
                "type": [
                   "VerifiableCredential",
                   "VaccinationCredential"
                ],
                "@context": [
                   "https://www.w3.org/2018/credentials/v1"
                ],
                "issuanceDate": "2021-03-17T13:18:37.000Z",
                "proof": {
                   "type": "JwtProof2020",
                   "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNTk4NzExNywiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.tGSAsEbF4bKb5bEWNtU1nItaMTYraSstaD2cxSfk9K13KZDOU07O3c6-2u9QKWpxHAm0ZhDGq9QQ07XDeGoqmw"
                }
             }
          ],
          "holder": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
          "verifier": [
             "did:infra:01:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz"
          ],
          "type": [
             "VerifiablePresentation"
          ],
          "@context": [
             "https://www.w3.org/2018/credentials/v1"
          ],
          "issuanceDate": "2021-03-17T13:38:49.000Z",
          "expirationDate": "2021-03-17T13:48:49.000Z",
          "proof": {
             "type": "JwtProof2020",
             "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJleHAiOjE2MTU5ODg5MjksInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUoyWXlJNmV5SmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpqYkdGcGJURWlPaUpqYkdGcGJURmZkbUZzZFdVaUxDSmpiR0ZwYlRJaU9pSmpiR0ZwYlRKZmRtRnNkV1VpZlN3aVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbFpoWTJOcGJtRjBhVzl1UTNKbFpHVnVkR2xoYkNKZGZTd2ljM1ZpSWpvaVpHbGtPbWx1Wm5KaE9qQXhPbEJWUWw5TE1WODNha05FWVhKWWJsb3pVMlJRUVhkbVJrVmphVlJUZVZWNlFUUm1ibVp1YTNSMlJrZzVSbW8zU2pnNVZYSkdhVWh3ZENJc0ltcDBhU0k2SW1oMGRIQTZMeTlsZUdGdGNHeGxMblpqTDJOeVpXUmxiblJwWVd4ekx6RXlNelV6TWlJc0ltNWlaaUk2TVRZeE5UazROekV4Tnl3aWFYTnpJam9pWkdsa09tbHVabkpoT2pBeE9sQlZRbDlMTVY4NFVIZEhOMjltTlVJNGNEbE5jR0YzTmxoNlpYbFpkRk5YU25sbFUxaFdkSGhhYUZCSVVVTTFaVnA0V2tOcmNXbE1WU0o5LnRHU0FzRWJGNGJLYjViRVdOdFUxbkl0YU1UWXJhU3N0YUQyY3hTZms5SzEzS1pET1UwN08zYzYtMnU5UUtXcHhIQW0wWmhER3E5UVEwN1hEZUdvcW13Il19LCJuYmYiOjE2MTU5ODgzMjksImlzcyI6ImRpZDppbmZyYTowMTpQVUJfSzFfN2pDRGFyWG5aM1NkUEF3ZkZFY2lUU3lVekE0Zm5mbmt0dkZIOUZqN0o4OVVyRmlIcHQiLCJhdWQiOlsiZGlkOmluZnJhOjAxOlBVQl9LMV81VGFFZ3BWdXIzOTFkaW1WbkZDREhCMTIyRFhZQmJ3V2RLVXBFSkNOdjNrbzFLTVl3eiJdfQ.ud6HTb2dI4d6epdKdmSl4gZXxJ_XDzRvmjIwRTeBUHxb-dHLWFPFYdA__t4OQgHV48ei9TSgP93Hs8f5GU_q8w"
          }
       }
    }
    */
    })
  })

})
