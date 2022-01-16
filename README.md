# Infra DID Javascript Library

* Infra DID Method Spec
  - https://github.com/InfraBlockchain/infra-did-method-specs/blob/main/docs/Infra-DID-method-spec.md

* Infra DID Registry Smart Contract on InfraBlockchain
  - https://github.com/InfraBlockchain/infra-did-registry

* Infra DID Resolver (DIF javascript universal resolver compatible)
  - https://github.com/InfraBlockchain/infra-did-resolver

Feature provided by infra-did-js library
  * Infra DID Creation
  * update DID attributes (service endpoint)
  * update Pub-Key DID owner key
  * revoke Pub-Key DID
  * VC/VP creation/verification using did-jwt-vc library 

### Infra DID API Configuration

```javascript
  import InfraDID from 'infra-did-js'
  
  const confBlockchainNetwork = {
    networkId: '01',
    registryContract: 'infradidregi',
    rpcEndpoint: 'https://api.testnet.infrablockchain.com',
    txfeePayerAccount: 'txfeepayeraa',
    txfeePayerPrivateKey: 'TXFEE_PAYER_PRIVATE_KEY',
  }
  const conf = {
    ...confBlockchainNetwork,
    did: `did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
    didOwnerPrivateKey: 'DID_OWNER_PRIVATE_KEY',
  }
  const didApi = new InfraDID(conf)
```

### Infra DID Creation

currently secp256k1 curve is supported 
```javascript
  const pubKeyDID = InfraDID.createPubKeyDIDsecp256k1(networkId)
  console.log({pubKeyDID})
```

```javascript
{
  pubKeyDID: {
    did: 'did:infra:01:PUB_K1_8KeFXUKBR9kctm3eafs2tgqK3XxcqsnHtRp2kjSdfDFSn3x4bK',
    publicKey: 'PUB_K1_8KeFXUKBR9kctm3eafs2tgqK3XxcqsnHtRp2kjSdfDFSn3x4bK',
    privateKey: 'PVT_K1_bNrCcAYzMox6JANhwSpNSq5e1e8bXbu3kL6aNvCCRQR5aEfFg'
  }
}
```

### Update DID attributes

Set Pub-Key DID Attribute 
```javascript
  const conf = {
    ...confBlockchainNetwork,
    did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
    didOwnerPrivateKey: 'PVT_K1_PRIVATE_KEY',
  }
  
  const didApi = new InfraDID(conf)
  const res = await didApi.setAttributePubKeyDID('svc/MessagingService', 'https://infradid.com/pk/3/mysvcr9')
  console.log(res.transaction_id)
```

Remove Pub-Key DID Attribute
```javascript
  const didApi = new InfraDID(conf)
  const res = await didApi.setAttributePubKeyDID('svc/MessagingService', '')
  console.log(res.transaction_id)
```

Clear Pub-Key DID chain data
```javascript
  const conf = {
    ...confBlockchainNetwork,
    did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
    didOwnerPrivateKey: 'PVT_K1_PRIVATE_KEY',
  }
  
  const didApi = new InfraDID(conf)
  const res = await didApi.clearPubKeyDID()
  console.log(res.transaction_id)
```

Set Account-based DID Attribute
```javascript
  const conf = {
    ...confBlockchainNetwork,
    did: `did:infra:01:jghpykcpaoko`,
    didOwnerPrivateKey: 'PVT_K1_PRIVATE_KEY',
  }
  
  const didApi = new InfraDID(conf)
  const res = await didApi.setAttributeAccountDID('svc/MessagingService', 'https://infradid.com/acc/1/mysvcr7')
  console.log(res.transaction_id)
```

Update Pub-Key DID owner key
```javascript
  const conf = {
    ...confBlockchainNetwork,
    did: `did:infra:01:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`,
    didOwnerPrivateKey: 'PVT_K1_PRIVATE_KEY',
  }
  
  const didApi = new InfraDID(conf)
  const res = await await didApi.changeOwnerPubKeyDID('PUB_K1_584qGNgteYFppoisbDz6vBFArrw3As8qeeRCekLepG4pJVrhJt')
  console.log(res.transaction_id)
```

### Revoke Pub-Key DID

```javascript
  const conf = {
    ...confBlockchainNetwork,
    did: `did:infra:${networkId}:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`,
    didOwnerPrivateKey: 'PVT_K1_PRIVATE_KEY',
  }
  
  const didApi = new InfraDID(conf)
  const resRevoke = await didApi.revokePubKeyDID()
  console.log(resRevoke.transaction_id)
```

### Issuing and Verifying W3C Verifiable Credential (VC), Verifiable Presentation (VP) using did-jwt-vc library 

```javascript
import InfraDID from 'infra-did-js'
import { Resolver } from 'did-resolver'
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

const infraDidResolverConfig = {
  networks : [
    {
      networkId,
      registryContract,
      rpcEndpoint
    }
  ]
}

const infraDidResolver = getResolver(infraDidResolverConfig)
const didResolver = new Resolver({...infraDidResolver})
```

#### Create and Verify Verifiable Credential Jwt

```javascript
  const vcIssuerDidConf = {
    ...confDefaults,
    did: `did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`,
    didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA',
  }
  
  const vcSubjectDid = `did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt`
  
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
  
  const vcJWT = await createVerifiableCredentialJwt(credential, issuer)
  const verifiedCredential = await verifyCredential(vcJWT, didResolver)
  console.log(JSON.stringify(verifiedCredential, null, 3))
```

Verified Credential Result
```json
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
      "nbf": 1617358301,
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
   "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNzM1ODMwMSwiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.ZByKShPxhKt2wlYsZQe6aGfxgjHuB1WW9X52cZjltMDLZEHJASXm7bsP5GwFG2dJtITYQ78NYgLXtLpRfLyxQQ",
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
      "issuanceDate": "2021-04-02T10:11:41.000Z",
      "proof": {
         "type": "JwtProof2020",
         "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNzM1ODMwMSwiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.ZByKShPxhKt2wlYsZQe6aGfxgjHuB1WW9X52cZjltMDLZEHJASXm7bsP5GwFG2dJtITYQ78NYgLXtLpRfLyxQQ"
      }
   }
}
```

#### Create and Verify Verifiable Presentation Jwt

```javascript
  const vcHolderDidConf = {
    ...confDefaults,
    did: `did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt`,
    didOwnerPrivateKey: 'PVT_K1_2NqB8nrfnd6Eqj46uQvvKXiwNj6rp7dp3iJjm4K86BJW4KGSVb',
  }
  
  const verifierDid = `did:infra:01:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`
  
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
  
  const verifiedPresentation = await verifyPresentation(vpJWT, didResolver, { audience: verifierDid })
  console.log(JSON.stringify(verifiedPresentation, null, 3))
```

Verified Presentation Result
```json
{
   "payload": {
      "exp": 1617359105,
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
      "nbf": 1617358505,
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
   "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJleHAiOjE2MTczNTkxMDUsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUoyWXlJNmV5SmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpqYkdGcGJURWlPaUpqYkdGcGJURmZkbUZzZFdVaUxDSmpiR0ZwYlRJaU9pSmpiR0ZwYlRKZmRtRnNkV1VpZlN3aVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbFpoWTJOcGJtRjBhVzl1UTNKbFpHVnVkR2xoYkNKZGZTd2ljM1ZpSWpvaVpHbGtPbWx1Wm5KaE9qQXhPbEJWUWw5TE1WODNha05FWVhKWWJsb3pVMlJRUVhkbVJrVmphVlJUZVZWNlFUUm1ibVp1YTNSMlJrZzVSbW8zU2pnNVZYSkdhVWh3ZENJc0ltcDBhU0k2SW1oMGRIQTZMeTlsZUdGdGNHeGxMblpqTDJOeVpXUmxiblJwWVd4ekx6RXlNelV6TWlJc0ltNWlaaUk2TVRZeE5UazROekV4Tnl3aWFYTnpJam9pWkdsa09tbHVabkpoT2pBeE9sQlZRbDlMTVY4NFVIZEhOMjltTlVJNGNEbE5jR0YzTmxoNlpYbFpkRk5YU25sbFUxaFdkSGhhYUZCSVVVTTFaVnA0V2tOcmNXbE1WU0o5LnRHU0FzRWJGNGJLYjViRVdOdFUxbkl0YU1UWXJhU3N0YUQyY3hTZms5SzEzS1pET1UwN08zYzYtMnU5UUtXcHhIQW0wWmhER3E5UVEwN1hEZUdvcW13Il19LCJuYmYiOjE2MTczNTg1MDUsImlzcyI6ImRpZDppbmZyYTowMTpQVUJfSzFfN2pDRGFyWG5aM1NkUEF3ZkZFY2lUU3lVekE0Zm5mbmt0dkZIOUZqN0o4OVVyRmlIcHQiLCJhdWQiOlsiZGlkOmluZnJhOjAxOlBVQl9LMV81VGFFZ3BWdXIzOTFkaW1WbkZDREhCMTIyRFhZQmJ3V2RLVXBFSkNOdjNrbzFLTVl3eiJdfQ.7fANbV48GUO9VeGCgNlJX5jY9MHAUCKTd1BPxAhRRwek7GK7e7lTmiX5qEBr0l5NimfpI8FY0vunWj-Mr0MCRA",
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
      "issuanceDate": "2021-04-02T10:15:05.000Z",
      "expirationDate": "2021-04-02T10:25:05.000Z",
      "proof": {
         "type": "JwtProof2020",
         "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJleHAiOjE2MTczNTkxMDUsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUoyWXlJNmV5SmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpqYkdGcGJURWlPaUpqYkdGcGJURmZkbUZzZFdVaUxDSmpiR0ZwYlRJaU9pSmpiR0ZwYlRKZmRtRnNkV1VpZlN3aVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbFpoWTJOcGJtRjBhVzl1UTNKbFpHVnVkR2xoYkNKZGZTd2ljM1ZpSWpvaVpHbGtPbWx1Wm5KaE9qQXhPbEJWUWw5TE1WODNha05FWVhKWWJsb3pVMlJRUVhkbVJrVmphVlJUZVZWNlFUUm1ibVp1YTNSMlJrZzVSbW8zU2pnNVZYSkdhVWh3ZENJc0ltcDBhU0k2SW1oMGRIQTZMeTlsZUdGdGNHeGxMblpqTDJOeVpXUmxiblJwWVd4ekx6RXlNelV6TWlJc0ltNWlaaUk2TVRZeE5UazROekV4Tnl3aWFYTnpJam9pWkdsa09tbHVabkpoT2pBeE9sQlZRbDlMTVY4NFVIZEhOMjltTlVJNGNEbE5jR0YzTmxoNlpYbFpkRk5YU25sbFUxaFdkSGhhYUZCSVVVTTFaVnA0V2tOcmNXbE1WU0o5LnRHU0FzRWJGNGJLYjViRVdOdFUxbkl0YU1UWXJhU3N0YUQyY3hTZms5SzEzS1pET1UwN08zYzYtMnU5UUtXcHhIQW0wWmhER3E5UVEwN1hEZUdvcW13Il19LCJuYmYiOjE2MTczNTg1MDUsImlzcyI6ImRpZDppbmZyYTowMTpQVUJfSzFfN2pDRGFyWG5aM1NkUEF3ZkZFY2lUU3lVekE0Zm5mbmt0dkZIOUZqN0o4OVVyRmlIcHQiLCJhdWQiOlsiZGlkOmluZnJhOjAxOlBVQl9LMV81VGFFZ3BWdXIzOTFkaW1WbkZDREhCMTIyRFhZQmJ3V2RLVXBFSkNOdjNrbzFLTVl3eiJdfQ.7fANbV48GUO9VeGCgNlJX5jY9MHAUCKTd1BPxAhRRwek7GK7e7lTmiX5qEBr0l5NimfpI8FY0vunWj-Mr0MCRA"
      }
   }
}
```
