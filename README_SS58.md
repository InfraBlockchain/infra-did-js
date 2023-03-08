# Infra SS58 DID Javascript Library

- Infra DID Method Spec

  - https://github.com/InfraBlockchain/infra-did-method-specs/blob/main/docs/Infra-DID-method-spec.md

- Infra DID Resolver (DIF ts universal resolver compatible)

  - https://github.com/InfraBlockchain/infra-did-resolver

- Infra DID Substrate Node

  - https://github.com/InfraBlockchain/infra-did-substrate

Feature provided by `infra-did-js/infra-ss58` library

- Infra SS58 DID Creation(SR25519, ED25519, Secp257K1)
- Register/Unregister DID on chain
- Update/Remove DID attributes (service endpoint, controller DID, public key)
- Set attestations claim
- Get Documents of DID(resolve)
- BBS+ KeyPair & public key Creation
- Add/Remove/Get BBS+ public key
- Add/Remove/Get BBS+ Params
- Register/Unregister registry on chain
- Create, register Schema
- Create/issue/verify/revoke/unrevoke Verifiable Credential
- Create/sign/verify VerifiablePresentation

## Infra SS58 DID API Configuration

```ts
import  {InfraSS58, CRYPTO_INFO} from 'infra-did-js';

const txfeePaterAccountKeyPair = await InfraSS58.getKeyPairFromUri('//Alice', CRYPTO_INFO.SR25519);
const confBlockchainNetwork = {
  networkId: 'space',
  address: 'wss://polkadot.infrablockchain.com',
  // seed or keyPair required
  txfeePayerAccountKeyPair,
  // or txfeePayerAccountSeed: 'TX_FEE_PAYER_ACCOUNT_SEED'
};
const conf = {
  ...confBlockchainNetwork,
  did: 'did:infra:space:5CRV5zBdAhBALnXiBSWZWjca3rSREBg87GJ6UY9i2A7y1rCs',
  // seed or keyPair required
  seed: 'DID_SEED',
  // keyPair: keyPair,
  controllerDID: 'did:infra:space:5HdJprb8NhaJsGASLBKGQ1bkKkvaZDaK1FxTbJRXNShFuqgY'
  controllerSeed: 'DID_CONTROLLER_SEED',
  // or controllerKeyPair: controllerKeyPair
};
const infraApi = await InfraSS58.createAsync(conf);
```

## Infra SS58 DID Creation

```ts
DIDSet = await InfraSS58.createNewSS58DIDSet(
  networkId,
  CRYPTO_INFO.SR25519 // or CRYPTO_INFO.ED25519 or CRYPTO_INFO.Secp256k1
)
console.log({ DIDSet })
```

```ts
{
  DIDSet: {
        did: 'did:infra:space:5FxjYbTe26dwcHKjBHxHUp14wqs1fU4iyTyKB5ff6uxcfCNy',
        didKey: DidKey_SS58 {
          publicKey: [PublicKey_SS58],
          verRels: [VerificationRelationship]
        },
        keyPair: {
          address: [Getter],
          addressRaw: [Getter],
          isLocked: [Getter],
          meta: [Getter],
          publicKey: [Getter],
          type: [Getter],
          // -- snip --
        },
        publicKey: PublicKey_SS58 {
          value: '0xac63251df26461e78f5f82f7271db9e4c82a02d8f9e43c001096821f8a54ee58',
          sigType: 'Sr25519'
        },
        verRels: VerificationRelationship { _value: 0 },
        cryptoInfo: {
          CRYPTO_TYPE: 'sr25519',
          KEY_TYPE: 'Sr25519VerificationKey2020',
          SIG_TYPE: 'Sr25519'
        },
        seed: '0x8b727f8418fdf7a01e76fc8a8e96d7e6c6b172fe9ae0e445e259ab38f911bf90'
      }
    }
}
```

## Infra SS58 DID Format Validation

```ts
InfraSS58.validateInfraSS58(SOME_DID_STRING).result
```

## OnCain DID

### Infra SS58 DID Register / unRegister OnChain

```ts
await infraApi.didModule.registerOnchain()
await infraApi.didModule.unregisterOnChain()
```

### Add keys

```ts
await infraApi.didModule.addKeys(SOME_DID_KEY)
```

### Remove keys

```ts
await infraApi.didModule.removeKeys(DID_KEY_IDS)
```

### Add Controller DID

```ts
await infraApi.didModule.addControllers(CONTROLLER_DIDS)
```

### Remove Controller DID

```ts
await infraApi.didModule.removeControllers(CONTROLLER_DIDS)
```

### Add Service Endpoint

```ts
await infraApi.didModule.addServiceEndpoint(SOME_SERVICE_ENDPOINT_URLS)
```

### Remove Service Endpoint

```ts
await infraApi.didModule.removeServiceEndpoint()
```

### Set Attestation Claim

```ts
await infraApi.didModule.setClaim(PRIORITY_NUMBER, CLAIM_IRI)
```

### Resolve DID Document(Temporary)

```ts
const didDocuments = await infraDID.didModule.getDocument()
// or
const didDocuments2 = await infraDID.getDocument(SOME_DID)

console.log({ didDocuments })
```

```json
{
  "didDocuments": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:infra:space:5EkFL4biewTM4eo5y4G1Bi5ArKU7993xRgQ94x3b29d1EgCb",
    "controller": [
      "did:infra:space:5EkFL4biewTM4eo5y4G1Bi5ArKU7993xRgQ94x3b29d1EgCb"
    ],
    "verificationMethod": [
      {
        "id": "did:infra:space:5EkFL4biewTM4eo5y4G1Bi5ArKU7993xRgQ94x3b29d1EgCb#keys-1",
        "type": "Sr25519VerificationKey2020", // 'unknown' if did not register chain
        "controller": "did:infra:space:5EkFL4biewTM4eo5y4G1Bi5ArKU7993xRgQ94x3b29d1EgCb",
        "publicKeyBase58": "8z5UyxcPoGSAUNVoczXdka3KcXCKVsAzRig7p96qmHos"
      }
    ],
    "authentication": [
      "did:infra:space:5EkFL4biewTM4eo5y4G1Bi5ArKU7993xRgQ94x3b29d1EgCb#keys-1"
    ],
    "assertionMethod": [
      "did:infra:space:5EkFL4biewTM4eo5y4G1Bi5ArKU7993xRgQ94x3b29d1EgCb#keys-1"
    ],
    "keyAgreement": [],
    "capabilityInvocation": [
      "did:infra:space:5EkFL4biewTM4eo5y4G1Bi5ArKU7993xRgQ94x3b29d1EgCb#keys-1"
    ],
    "ATTESTS_IRI": null,
    "service": []
  }
};
```

## BBS+

### BBS+ SigSet Creation

```ts
const newSigSet = InfraSS58.BBSPlus_createNewSigSet(MESSAGE_COUNTER_NUMBER)
const newSigSetByDID = await infraSS58.bbsModule.createNewSigSet(
  PARAM_COUNTER_NUMBER
)
console.log({ newSigSet })
```

```js
{
  newSigSet: {
     {
      sigSet: {
        sigParam: SignatureParamsG1 { value: [Object], label: undefined },
        keyPair: KeypairG2 { sk: [BBSPlusSecretKey], pk: [BBSPlusPublicKeyG2] },
        publicKey: {
          bytes: '0xe9f99021d89e072454bd13eeb8bf08343282d2a25a842be02315c342ede11019cdfc9c3dd97408595b56cda4abaf980014355d7de9da92122619c320618d1fd932b4a2219c087e7783beec0517261716c5a5fa10999f621ef308dc017656e598',
          paramsRef: undefined,
          curveType: 'Bls12381'
        },
        messageCounter: 10,
        label: undefined
      }
    };
```

### Add BBS+ Params

```ts
const sigParam = InfraSS58.BBSPlus_createSigParamsWithLabel(
  MESSAGE_COUNTER_NUMBER,
  'some-param-label'
)
await infraSS58.bbsModule.addParams(sigParam)
```

### Get BBS+ Params

```ts
const param = await infraDID.bbsModule.getParams(PARAM_COUNTER_NUMBER)
const lastParam = await infraDID.bbsModule.getLastParamsWritten()
```

### Remove BBS+ Params

```ts
await infraDID.bbsModule.removeParams(PARAM_COUNTER_NUMBER)
```

### Add BBS+ Public Key

```ts
await infraDID.bbsModule.addPublicKey(SigSet.publicKey)
```

### Get BBS+ Public Key

```ts
const publicKey = await infraDID.bbsModule.getPublicKey(KEY_ID_NUMBER)
console.log({ publicKey })
```

```json
{
  "publicKey": {
    "bytes": "0xe9f99021d89e072454bd13eeb8bf08343282d2a25a842be02315c342ede11019cdfc9c3dd97408595b56cda4abaf980014355d7de9da92122619c320618d1fd932b4a2219c087e7783beec0517261716c5a5fa10999f621ef308dc017656e598",
    "paramsRef": undefined,
    "curveType": "Bls12381"
  }
}
```

### Remove BBS+ Public Key

```ts
await infraDID.bbsModule.removePublicKey(KEY_ID_NUMBER)
```

## Schema

### Create schema

```ts
let schema = new Schema(newtworkId)
const someJSONSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  description: 'Schema Example',
  type: 'object',
  properties: {
    id: { type: 'string' },
    email: { type: 'string', format: 'email' },
    alumniOf: { type: 'string' }
  },
  required: ['email', 'alumniOf'],
  additionalProperties: false
}
schema = await schema.setJSONSchema(someJSONSchema)
console.log(schema.toJSON())
```

```json
{
  "id": "blob:infra:space:5EEmkHUNgMxL6435o7hfURpfNWtCdsVsvm5SD2y5oXmeUagM",
  "schema": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "description": "Schema Example",
    "type": "object",
    "properties": {
      "id": {
        "type": "string"
      },
      "email": {
        "type": "string",
        "format": "email"
      },
      "alumniOf": {
        "type": "string"
      }
    },
    "required": ["email", "alumniOf"],
    "additionalProperties": false
  }
}
```

### Register schema on chain

```ts
await infraApi.blobModule.writeSchemaOnChainByBlob(schema.toBlob())
// or
await schema.writeToChain(infraApi)
```

### Read schema on chain

```ts
await infraApi.blobModule.getSchema(schemaId)
// or
await Schema.get(schemaId, infraApi)
```

### Validate schema

```ts
const validationResult = await Schema.validateSchema(schema.schema)
console.log(validationResult)
```

```json
{
  "instance": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "description": "Schema Example",
    "type": "object",
    "properties": {
      "id": ["Object"],
      "email": ["Object"],
      "alumniOf": ["Object"]
    },
    "required": ["email", "alumniOf"],
    "additionalProperties": false
  },
  "schema": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "http://json-schema.org/draft-07/schema#",
    "title": "Core schema meta-schema",
    "definitions": {
      "schemaArray": ["Object"],
      "nonNegativeInteger": ["Object"],
      "nonNegativeIntegerDefault0": ["Object"],
      "simpleTypes": ["Object"],
      "stringArray": ["Object"]
    },
    "type": ["object", "boolean"],
    "properties": {
      // -- snip --
    },
    "default": true
  },
  "options": {
    "throwError": true,
    "throwAll": "undefined"
  },
  "path": [],
  "propertyPath": "instance",
  "errors": [],
  "throwError": true,
  "throwFirst": "undefined",
  "throwAll": "undefined",
  "disableFormat": false
}
```

## Verifiable Credential

### Add new registry

```ts
// create registry id
const registryId = issuerApi.revocationModule.createNewRegistryId()
// add new registry
await issuerApi.revocationModule.newRegistry(registryId)
// get registry
await issuerApi.revocationModule.getRevocationRegistry(registryId)
```

### Create Verifiable Credential

```ts
vc = new VerifiableCredential(VC_ID)
vc.addContext('https://www.w3.org/2018/credentials/examples/v1')
vc.addContext('https://www.w3.org/2018/credentials/v1')
vc.addContext('https://schema.org')
vc.addType('VerifiableCredential')
vc.addType('VaccinationCredential')
vc.setSchema(schemaId, 'JsonSchemaValidator2018')
vc.addSubject({
  id: HOLDER_DID,
  alumniOf: 'Example University',
  email: 'test@test.com'
})
vc.setIssuanceDate('2021-04-02T10:11:41.000Z')
console.log(vc.toJSON())
```

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://schema.org"
  ],
  "id": "http://example.vc/credentials/123532",
  "type": ["VerifiableCredential", "VaccinationCredential"],
  "credentialSubject": [
    {
      "id": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3",
      "alumniOf": "Example University",
      "email": "test@test.com"
    }
  ],
  "issuanceDate": "2021-04-02T10:11:41.000Z",
  "credentialSchema": {
    "id": "blob:infra:space:5EEmkHUNgMxL6435o7hfURpfNWtCdsVsvm5SD2y5oXmeUagM",
    "type": "JsonSchemaValidator2018"
  }
}
```

### Issue(Sign) Verifiable Credential

```ts
const signedVC = await vc.sign(issuerInfraApi.getKeyDoc())
console.log(signedVC.toJSON())
```

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://schema.org"
  ],
  "id": "http://example.vc/credentials/123532",
  "type": ["VerifiableCredential", "VaccinationCredential"],
  "credentialSubject": [
    {
      "id": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3",
      "alumniOf": "Example University",
      "email": "test@test.com"
    }
  ],
  "issuanceDate": "2021-04-02T10:11:41.000Z",
  "credentialSchema": {
    "id": "blob:infra:space:5EEmkHUNgMxL6435o7hfURpfNWtCdsVsvm5SD2y5oXmeUagM",
    "type": "JsonSchemaValidator2018"
  },
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-03-08T05:06:06Z",
    "verificationMethod": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "zAN1rKvtTouag9xApsQx1meZYG6bsDbMBN3dPiuBrsYJLKDzskZeZmRunwCjFGANBAsv7PfzbGuL7Ye9XPiDgWJbBXkSiRRAgs"
  },
  "issuer": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs"
}
```

### Validate Credential schema

```ts
const result: boolean = await signedVC.validateSchema(schema)
```

### Verify Verifiable Credential

```ts
const verifyResult = await signedVC.verify(issuerApi)
console.log(verifyResult)
```

```json
{
  "verified": true,
  "results": [
    {
      "proof": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
          "https://schema.org"
        ],
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-03-08T05:06:06Z",
        "verificationMethod": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "zAN1rKvtTouag9xApsQx1meZYG6bsDbMBN3dPiuBrsYJLKDzskZeZmRunwCjFGANBAsv7PfzbGuL7Ye9XPiDgWJbBXkSiRRAgs"
      },
      "verified": true,
      "verificationMethod": {
        "@context": "https://w3id.org/security/v2",
        "id": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": {
          "id": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs",
          "assertionMethod": [
            "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
          ],
          "authentication": [
            "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
          ],
          "capabilityInvocation": [
            "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
          ],
          "controller": "did:infra:space5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs",
          "verificationMethod": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
        },
        "publicKeyBase58": "rmwTxfjnpCM5wncDQ8k7RmCbzkY34BfTiKdw5QVNfRda"
      },
      "purposeResult": {
        "valid": true,
        "error": null
      }
    }
  ]
}
```

### Revoke/Unrevoke/ Verifiable Credential

```ts
const revokeId = issuerApi.revocationModule.getRevokeId(VC_ID)
// revoke vc
await issuerApi.revocationModule.revokeCredentialWithOneOfPolicy(
  registryId,
  revokeId
)
// unrevoke vc
await issuerApi.revocationModule.unrevokeCredentialWithOneOfPolicy(
  registryId,
  revokeId
)
//chack revoke state
const isRevoked: boolean = await issuerApi.revocationModule.getIsRevoked(
  registryId,
  revokeId
)
```

## Verifiable Presentation

### Create Verifiable Presentation

```ts
vp = new VerifiablePresentation(VP_ID)
vp.addContext('https://www.w3.org/2018/credentials/examples/v1')
vp.addType('CredentialManagerPresentation')
vp.setHolder(HOLDER_DID)
vp.addCredential(vc)
console.log(vp.toJSON())
```

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "verifiableCredential": [
    {
      "@context": ["Array"],
      "id": "http://example.vc/credentials/123532",
      "type": ["Array"],
      "credentialSubject": ["Array"],
      "issuanceDate": "2021-04-02T10:11:41.000Z",
      "credentialSchema": ["Object"],
      "proof": ["Object"],
      "issuer": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs"
    }
  ],
  "id": "http://example.edu/credentials/2803",
  "type": ["VerifiablePresentation", "CredentialManagerPresentation"],
  "proof": null,
  "holder": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3"
}
```

### Sign Verifiable Presentation

```ts
const signedVP = await vp.sign(holderInfraApi, DOMAIN_URL)
console.log(signedVP)
```

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "verifiableCredential": [
    {
      "@context": ["Array"],
      "id": "http://example.vc/credentials/123532",
      "type": ["Array"],
      "credentialSubject": ["Array"],
      "issuanceDate": "2021-04-02T10:11:41.000Z",
      "credentialSchema": ["Object"],
      "proof": ["Object"],
      "issuer": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs"
    }
  ],
  "id": "http://example.edu/credentials/2803",
  "type": ["VerifiablePresentation", "CredentialManagerPresentation"],
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2023-03-08T05:06:12Z",
    "verificationMethod": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1",
    "proofPurpose": "authentication",
    "challenge": "0xf805d8827cce9d4a49e1c30efd5f96a34dc726b7e50908d07e92f525be8bd068",
    "domain": "example domain",
    "proofValue": "zkt1MCJ6uZMHUS67uuAYzXJKtvymYh7oiFmzyXbPA2BCQME5T8NqqR6cw3vwu2dy2ZY82tSfJ45Hh8a5YjXmB766"
  },
  "holder": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3"
}
```

### Verify Verifiable Presentation

```ts
const verifyResult = await signedVP.verify(verifierInfraApi, DOMAIN_URL)
console.log(verifyResult)
```

```json
{
  "presentationResult": {
    "verified": true,
    "results": [
      {
        "proof": {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
          ],
          "type": "Ed25519Signature2018",
          "created": "2023-03-08T05:06:12Z",
          "verificationMethod": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1",
          "proofPurpose": "authentication",
          "challenge": "0xf805d8827cce9d4a49e1c30efd5f96a34dc726b7e50908d07e92f525be8bd068",
          "domain": "example domain",
          "proofValue": "zkt1MCJ6uZMHUS67uuAYzXJKtvymYh7oiFmzyXbPA2BCQME5T8NqqR6cw3vwu2dy2ZY82tSfJ45Hh8a5YjXmB766"
        },
        "verified": true,
        "verificationMethod": {
          "@context": "https://w3id.org/security/v2",
          "id": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1",
          "type": "Ed25519VerificationKey2018",
          "controller": {
            "id": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3",
            "assertionMethod": [
              "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1"
            ],
            "authentication": [
              "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1"
            ],
            "capabilityInvocation": [
              "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1"
            ],
            "controller": "did:infra:space5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3",
            "verificationMethod": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1"
          },
          "publicKeyBase58": "5PtpUtVRvqRdpq34RFn3sYkHMisNUcNz97bs2jP6hLMj"
        },
        "purposeResult": {
          "valid": true,
          "controller": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3",
            "controller": [
              "did:infra:space5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3"
            ],
            "verificationMethod": [
              {
                "id": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3",
                "publicKeyBase58": "5PtpUtVRvqRdpq34RFn3sYkHMisNUcNz97bs2jP6hLMj"
              }
            ],
            "authentication": [
              "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1"
            ],
            "assertionMethod": [
              "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1"
            ],
            "keyAgreement": [],
            "capabilityInvocation": [
              "did:infra:space:5DYKafDzPZSfJ5jmcAQK5X1TAShwbAPJJPzetUKv2XQuBBL3#keys-1"
            ],
            "ATTESTS_IRI": null,
            "service": []
          }
        }
      }
    ]
  },
  "credentialResults": [
    {
      "verified": true,
      "results": [
        {
          "proof": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://www.w3.org/2018/credentials/examples/v1",
              "https://schema.org"
            ],
            "type": "EcdsaSecp256k1Signature2019",
            "created": "2023-03-08T05:06:06Z",
            "verificationMethod": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "zAN1rKvtTouag9xApsQx1meZYG6bsDbMBN3dPiuBrsYJLKDzskZeZmRunwCjFGANBAsv7PfzbGuL7Ye9XPiDgWJbBXkSiRRAgs"
          },
          "verified": true,
          "verificationMethod": {
            "@context": "https://w3id.org/security/v2",
            "id": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1",
            "type": "EcdsaSecp256k1VerificationKey2019",
            "controller": {
              "id": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs",
              "assertionMethod": [
                "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
              ],
              "authentication": [
                "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
              ],
              "capabilityInvocation": [
                "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
              ],
              "controller": "did:infra:space5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs",
              "verificationMethod": "did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"
            },
            "publicKeyBase58": "rmwTxfjnpCM5wncDQ8k7RmCbzkY34BfTiKdw5QVNfRda"
          },
          "purposeResult": {
            "valid": true,
            "error": null
          }
        }
      ],
      "credentialId": "http://example.vc/credentials/123532"
    }
  ],
  "verified": true
}
```
