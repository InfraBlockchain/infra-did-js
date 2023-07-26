---
marp: true
theme: gaia
paginate: true
style: |
  .columns {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 1rem;
  }
   .columns-left {
    background: yellow;
  }
  .columns-right {
    background: beige;
  }
---

<!-- Documents written in marpit-markdown. -->

<style>
section::after {
    font-size: 16px;
    content: attr(data-marpit-pagination) ' / ' attr(data-marpit-pagination-total);
}

</style>

<!-- _class: lead -->

# Infra SS58 DID Javascript Library

---

## Reference

- Infra DID Method Spec

  - https://github.com/InfraBlockchain/infra-did-method-specs/blob/main/docs/Infra-DID-method-spec.md

- Infra DID Resolver (DIF ts universal resolver compatible)

  - https://github.com/InfraBlockchain/infra-did-resolver

- Infra DID Substrate Node

  - https://github.com/InfraBlockchain/infra-did-substrate

---

## Note

- The Infra DID resolver provides three types of verification methods in its DID document: 'Ed25519VerificationKey2018', 'Ed25519VerificationKey2020', and 'JsonWebKey2020'.
- However, as of 2023-07-21, we are using the [w3c standard](https://w3c-ccg.github.io/security-vocab/contexts/security-v2.jsonld) for VC/VP verification, so only 'Ed25519VerificationKey2018' is available.

---

## Feature(1/4)

- Infra SS58 DID Creation
- DID Module
  - Register/Unregister DID on chain
  - Update/Remove DID attributes
    - Service Endpoint, Controller DID, Public Key
  - Set Attestations Claim
  - Get Documents of DID(Resolve)

---

## Feature(2/4)

- BBS+ Module
  - BBS+ Key Pair & Public Key Creation
  - Add/Get/Remove BBS+ Params
  - Add/Get/Remove BBS+ Public Key
- Trusted Entity Module
  - Register/Get/Unregister Authorizer on chain
  - Add/Get/Remove Trusted Entity(Issuer, Verifier)
- Registry Module
  - Register/Get/Unregister Registry on chain

---

## Feature(3/4)

- Verifiable Classes
  - Create/Register/Get Schema
  - Create/Issue/Verify Verifiable Credential
  - Revoke/Unrevoke/Check Verifiable Credential
  - Create/Sign/Verify VerifiablePresentation
  - Issue/Verify BBSPlusCredential and BBSPlusPresentation

---

## Feature(4/4)

- Crypto Helper
  - Convert Ed25519 to X25519
  - Convert key type (u8a to jwk, keyobject)
  - Create ECDH-ES Key(diffieHellman) using X25519
  - ED25519 derived key [SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)

---

## Infra SS58 DID API Configuration

```ts
import  {InfraSS58, CRYPTO_INFO} from 'infra-did-js';

const txfeePaterAccountKeyPair = await InfraSS58.getKeyPairFromUri('//Alice', 'sr25519');const conf = {
  networkId: 'space',
  address: 'wss://infra2.infrablockchain.com',
  // seed or keyPair required
  txfeePayerAccountKeyPair,
  // or txfeePayerAccountSeed: 'TX_FEE_PAYER_ACCOUNT_SEED'
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

---

## Infra SS58 DID Creation

```ts
DIDSet = await InfraSS58.createNewSS58DIDSet(networkId);
console.log({ DIDSet });
```

---

```ts
{
  DIDSet: {
    did: 'did:infra:space:5Cq2Za1Z4HJx5eTvxT5iFyXZLM1XTwVZSafQsEuK4ujNKJEF',
    didKey: DidKey_SS58 {
      publicKey: PublicKey_SS58 {
      value: '0x21cdc3dc94f8cccd889759fbc282f4272f89c8d974aea4d3051e8efa85e738b7',
      sigType: 'Ed25519'
    },
    verRels: VerificationRelationship { _value: 0 }
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
      value: '0x21cdc3dc94f8cccd889759fbc282f4272f89c8d974aea4d3051e8efa85e738b7',
      sigType: 'Ed25519'
    },
    verRels: VerificationRelationship { _value: 0 },
    cryptoInfo: {
      CRYPTO_TYPE: 'ed25519',
      KEY_NAME: 'Ed25519VerificationKey2018',
      SIG_TYPE: 'Ed25519',
      SIG_NAME: 'Ed25519Signature2018',
      SIG_CLS: [class Ed25519Signature2018 extends CustomLinkedDataSignature],
      LDKeyClass: [class Ed25519VerificationKey2018]
    },
    seed: '0x8c9971953c5c82a51e3ab0ec9a16ced7054585081483e2489241b5b059f5f3cf',
    keyPairJWK: {
      publicJwk: {
        alg: 'EdDSA',
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'Ic3D3JT4zM2Il1n7woL0Jy-JyNl0rqTTBR6O-oXnOLc'
      },
      privateJwk: {
        alg: 'EdDSA',
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'Ic3D3JT4zM2Il1n7woL0Jy-JyNl0rqTTBR6O-oXnOLc',
        d: 'jJlxlTxcgqUeOrDsmhbO1wVFhQgUg-JIkkG1sFn1888'
      }
    }
  }
}
```

---

## Infra SS58 DID Format Validation

```ts
InfraSS58.validateInfraSS58(SOME_DID_STRING).result;
```

---

<!-- _class: lead -->

## DID Module

<!--footer: "DID Module" -->

---

### Register / Unregister Infra SS58 DID OnChain

```ts
// Register DID
await infraApi.didModule.registerOnchain();
// Unregister DID
await infraApi.didModule.unregisterOnChain();
```

---

### Add/Remove keys

```ts
// Add keys
await infraApi.didModule.addKeys(SOME_DID_KEY);
// Remove Keys
await infraApi.didModule.removeKeys(DID_KEY_IDS);
```

---

### Add/Remove Controller DID

```ts
// Add Controller DID
await infraApi.didModule.addControllers(CONTROLLER_DIDS);
// Remove Controller DID
await infraApi.didModule.removeControllers(CONTROLLER_DIDS);
```

---

### Add/Get/Remove Service Endpoint

```ts
// Add Service Endpoint
await infraApi.didModule.addServiceEndpoint(SOME_SERVICE_ENDPOINT_URLS);
// Get Service Endpoint
await infraApi.didModule.getServiceEndpoint();
// Remove Service Endpoint
await infraApi.didModule.removeServiceEndpoint();
```

---

### Set Attestation Claim

```ts
await infraApi.didModule.setClaim(PRIORITY_NUMBER, CLAIM_IRI);
```

---

### Resolve DID Document

```ts
// get self.document
const didDocuments = await infraDID.didModule.getDocument();
// or get some did document
const didDocuments2 = await infraDID.getDocument(SOME_DID);

console.log({ didDocuments });
```

---

```json
{
  "didDocuments": {
    "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX",
      "controller": [
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX"
      ],
      "verificationMethod": [
        {
          "id": "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-1",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX",
          "publicKeyBase58": "FXvzvY3jcmtXNK48azNRund96FBFtVK62MMPHZeE1v7T"
        },
        {
          "id": "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-2",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX",
          "publicKeyMultibase": "zFXvzvY3jcmtXNK48azNRund96FBFtVK62MMPHZeE1v7T"
        },
        {
          "id": "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-3",
          "type": "JsonWebKey2020",
          "controller": "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX",
          "publicKeyJwk": {
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "keys-3",
            "x": "1_AZBSwM9m5V0JvdNHro1FzkHi38m50V6N_fR_DaGdo"
          }
        }
      ],
      "authentication": [
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-1",
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-2",
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-3"
      ],
      "assertionMethod": [
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-1",
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-2",
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-3"
      ],
      "keyAgreement": [],
      "capabilityInvocation": [
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-1",
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-2",
        "did:infra:space:5GwqUaWxLMqZeC5bK7XgEQ1ZNL8y9YnxxvtVFSnoFtzRWfiX#keys-3"
      ],
      "ATTESTS_IRI": null,
      "service": []
  }
};
```

---

<!-- _class: lead -->

## BBS+ Module

<!--footer: "BBS+ Module" -->

---

### BBS+ SigSet Creation

```ts
const newSigSet = await InfraSS58.BBSPlus_createNewSigSet(did);
console.log({
  newSigSet
});
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

---

### Add/Get/Remove BBS+ Params

```ts
// Create Sig Param
const sigParam = InfraSS58.BBSPlus_createSigParamsWithLabel(MESSAGE_COUNTER_NUMBER, 'some-param-label');
// Add BBS+ Params
await infraSS58.bbsModule.addParams(sigParam);
// Get BBS+ Params
const param = await infraDID.bbsModule.getParams(PARAM_COUNTER_NUMBER);
// Get BBS+ Last Params
const lastParam = await infraDID.bbsModule.getLastParamsWritten();
// Remove BBS+ {arams
await infraDID.bbsModule.removeParams(PARAM_COUNTER_NUMBER);
```

---

### Add/Get/Remove BBS+ Public Key

```ts
// Add BBS+ Public Key
await infraDID.bbsModule.addPublicKey(SigSet.publicKey);
// Get BBS+ Public Key
const publicKey = await infraDID.bbsModule.getPublicKey(KEY_ID_NUMBER);
console.log({
  publicKey
});
// Remove BBS+ Public Key
await infraDID.bbsModule.removePublicKey(KEY_ID_NUMBER);
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

---

<!-- _class: lead -->

## Trusted Entity Module

<!--footer: "Trusted Entity Module" -->

---

### Add/Get/Remove Authorizer

```ts
// Create Authorizer id
const authorizerId = infraSS58.trustModule.createNewAuthorizerId();
// Add Owner DID if want
infraSS58.trustModule.addPolicyOwner('some did');
// Add new Authorizer
await infraSS58.trustModule.registerAuthorizer(authorizerId);
// Get Authorizer
await infraSS58.trustModule.getAuthorizer(authorizerId);
// Remove Authorizer
await infraSS58.trustModule.unregisterAuthorizer(authorizerId);
```

---

### Add/Get/Remove Issuer

```ts
// Add Issuer
await infraSS58.trustModule.addIssuer(authorizerId, issuerDID);
// Get Issuer
await infraSS58.trustModule.getIssuers(authorizerId, issuerDID);
// Remove Issuer
await infraSS58.trustModule.removeIssuer(authorizerId, issuerDID);
```

---

### Add/Get/Remove Verifier

```ts
// Add Issuer
await infraSS58.trustModule.addVerifier(authorizerId, verifierDID);
// Get Issuer
await infraSS58.trustModule.getVerifiers(authorizerId, verifierDID);
// Remove Issuer
await infraSS58.trustModule.removeVerifier(authorizerId, verifierDID);
```

---

<!-- _class: lead -->

## Schema Class

<!--footer: "Schema Class" -->

---

### Create Schema

```ts
let schema = new Schema(newtworkId);
const someJSONSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  description: 'Schema Example',
  type: 'object',
  properties: {
    id: {
      type: 'string'
    },
    email: {
      type: 'string',
      format: 'email'
    },
    alumniOf: {
      type: 'string'
    }
  },
  required: ['email', 'alumniOf'],
  additionalProperties: false
};
schema = await schema.setJSONSchema(someJSONSchema);
console.log(schema.toJSON());
```

---

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

---

### Register/Get Schema on chain

```ts
// Register Schema
await infraApi.blobModule.writeSchemaOnChainByBlob(schema.toBlob());
// or
await schema.writeToChain(infraApi);

// Get Schema
await infraApi.blobModule.getSchema(schemaId);
// or
await Schema.get(schemaId, infraApi);
```

---

### Validate Schema

```ts
const validationResult = await Schema.validateSchema(schema.schema);
console.log(validationResult);
```

---

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

---

<!-- _class: lead -->

## Verifiable Credential Class

<!--footer: "Verifiable Credential Class" -->

---

### Register/Get/Unregister Registry

```ts
// Create new Registry id
const registryId = issuerApi.registryModule.createNewRegistryId();
// Register Registry
await issuerApi.registryModule.registerRegistry(registryId);
// Get Registry
await issuerApi.registryModule.getRegistry(registryId);
// Unregister Registry
await issuerApi.registryModule.unregisterRegistry(registryId);
```

---

### Create Verifiable Credential

```ts
vc = new VerifiableCredential(VC_ID);
vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
vc.addContext('https://www.w3.org/2018/credentials/v1');
vc.addContext('https://schema.org');
vc.addType('VerifiableCredential');
vc.addType('VaccinationCredential');
vc.setSchema(schemaId);
vc.addSubject({
  id: HOLDER_DID,
  alumniOf: 'Example University',
  email: 'test@test.com'
});
vc.setIssuanceDate('2021-04-02T10:11:41.000Z');
console.log(vc.toJSON());
```

---

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1", "https://schema.org"],
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

---

### Issue(Sign) Verifiable Credential

```ts
const signedVC = await vc.sign(issuerInfraApi.didModule.getKeyDoc());
console.log(signedVC.toJSON());
```

---

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1", "https://schema.org"],
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

---

### Validate Credential Schema

```ts
const result: boolean = await signedVC.validateSchema(schema);
```

---

### Verify Verifiable Credential

```ts
const verifyResult = await signedVC.verify(issuerApi);
console.log(verifyResult);
```

---

```json
{
  "verified": true,
  "results": [
    {
      "proof": {
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1", "https://schema.org"],
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
          "assertionMethod": ["did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"],
          "authentication": ["did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"],
          "capabilityInvocation": ["did:infra:space:5C8VZ28vrCbjsYeJrfNiy2TDSUDpCrRvya2RDy2KtbD6RFvs#keys-1"],
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

---

### Revoke/Unrevoke/Check Verifiable Credential

```ts
const revokeId = issuerApi.registryModule.getRevokeId(VC_ID);
// Revoke VC
await issuerApi.registryModule.revokeCredential(registryId, revokeId);
// Unrevoke VC
await issuerApi.registryModule.unrevokeCredential(registryId, revokeId);
// Check Revoke state
const isRevoked: boolean = await issuerApi.registryModule.getIsRevoked(registryId, revokeId);
```

---

<!-- _class: lead -->

## Verifiable Presentation Class

<!--footer: "Verifiable Presentation Class" -->

---

### Create Verifiable Presentation

```ts
vp = new VerifiablePresentation(VP_ID);
vp.addContext('https://www.w3.org/2018/credentials/examples/v1');
vp.addType('CredentialManagerPresentation');
vp.setHolder(HOLDER_DID);
vp.addCredential(vc);
console.log(vp.toJSON());
```

---

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
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

---

### Sign Verifiable Presentation

```ts
const signedVP = await vp.sign(holderInfraApi, DOMAIN_URL);
console.log(signedVP);
```

---

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
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

---

### Verify Verifiable Presentation

```ts
const verifyResult = await signedVP.verify(verifierInfraApi, DOMAIN_URL);
console.log(verifyResult);
```

---

```json
{
  "presentationResult": {
    "verified": true,
    "results": [
      /* snip */
    ]
  },
  "credentialResults": [
    {
      "verified": true,
      "results": [
        {
          "proof": {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://schema.org"],
            "type": "Ed25519Signature2018",
            "created": "2023-07-20T23:46:54Z",
            "verificationMethod": "did:infra:space:5FXBmypmPrqsp9pSrcJB3En2bdVYmA6T2C3aRXqjEMmLGBcR#keys-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z2TZV4YPEymjXp7CbpUtJD29ABXKRCRXhCyWfcZcg2foBkrab2h417tANL5DDEBumKC77hJsMkUKNL5KQZAe6KfAd"
          },
          "verified": true,
          "verificationMethod": {
            "@context": "https://w3id.org/security/v2",
            "id": "did:infra:space:5FXBmypmPrqsp9pSrcJB3En2bdVYmA6T2C3aRXqjEMmLGBcR#keys-1",
            "type": "Ed25519VerificationKey2018",
            "controller": {
              /* snip */
            },
            "publicKeyBase58": "BHsKsCtp9uovx1PefquegpVJtJJEEaR8A7agjeMRuSCs"
          },
          "purposeResult": {
            "valid": true,
            "error": null
          }
        }
      ],
      "credentialId": "did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U"
    }
  ],
  "verified": true
}
```

---

<!-- _class: lead -->

## BBSPlusPresentation Class

<!--footer: "BBSPlusPresentation Class" -->

---

### Prepare(add BBS+ Public Key, Schema, Credential)

```ts
// Add BBS+ Public Key and Key Pair ID
issuerBBSSigSet = await InfraSS58.BBSPlus_createNewSigSet(issuer.did);
await issuerApi.bbsModule.addPublicKey(issuerBBSSigSet.publicKey);
await issuerApi.didModule.getDocument().then((doc) => {
  issuerBBSSigSet.keyPair.id = doc.verificationMethod[1].id;
});
// Create Verifiable Credential
vc = new VerifiableCredential(vcId);
vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
vc.addContext('https://www.w3.org/2018/credentials/v1');
vc.addContext('https://schema.org');
vc.addType('VerifiableCredential');
vc.addType('VaccinationCredential');
// Different parts than normal Verifiable Credential
vc.setSchema(schema.toBBSSchema()); // Use toBBSSchema for schema,
// Use setSubject because BBSPlusPresentation does not allow arrays.
vc.setSubject({
  id: holder.did,
  alumniOf: 'Example University',
  email: 'test@test.com'
});
vc.setIssuer(issuer.did);
bbsPlusPresentation = new BBSPlusPresentation();
```

---

### Sign/Issue BBSPlusCredential

```ts
// Sign / Issue BBSPlusCredential
const { id, type } = issuerBBSSigSet.keyPair;
const issuerKeyDoc = issuerApi.getKeyDoc(
  id,
  issuer.did,
  type,
  issuerBBSSigSet.keyPair //use BBS+ keypair
);
const bbsPlusCredential = await bbsPlusPresentation.issueCredential(issuerKeyDoc, vc.toJSON());
```

---

### Create BBSPlusPresentation

```ts
// Add Presentation and reveal Attribute
const idx = await bbsPlusPresentation.addCredentialToPresent(bbsPlusCredential, {
  resolver: issuerApi.Resolver
});
await bbsPlusPresentation.addCredentialSubjectAttributeToReveal(idx, ['alumniOf']);

const presentation = await bbsPlusPresentation.createPresentation();
console.log({ presentation });
```

---

```json
{
  "version": "0.0.1",
  "nonce": null,
  "spec": {
    "credentials": [
      {
        "version": "0.1.0",
        "schema": "schemauri" //--snip--,
        "revealedAttributes": {
          "@context": "[\"https://www.w3.org/2018/credentials/v1\",
          \"https://www.w3.org/2018/credentials/examples/v1\",
          \"https://schema.org\"]",
          "type": "[\"VerifiableCredential\",\"VaccinationCredential\"]",
          "proof": {
            "type": "Bls12381BBS+SignatureDock2022",
            "verificationMethod": "did:infra:space:5EAFA4cfWyj6G7xxDWhAdCDcCTdh1tWenFzFaduTH8Mq2eCd#keys-2"
          },
          "credentialSubject": {
            "alumniOf": "Example University"
          }
        }
      }
    ],
    "attributeEqualities": []
  },
  "attributeCiphertexts": {},
  "proof": "SOME_PROOF" // -- snip --
}
```

---

### Verify BBSPlusPresentation

```ts
const verifyResult = await bbsPlusPresentation.verifyPresentation(presentation, {
  resolver: issuerApi.Resolver
});
```

---

<!-- _class: lead -->

## Crypto Helper

<!--footer: "CryptoHelper Class" -->

---

### Convert Key

```ts
const holder = await InfraSS58.createNewSS58DIDSet('space');
const publicKey = hexToU8a(verifier.publicKey.toJSON()['Ed25519']);
// convert Ed25519 to X25519
const xPkU8a = CryptoHelper.edPkToX25519Pk(publicKey, 'u8a');
const xPkJwk = CryptoHelper.edPkToX25519Pk(publicKey, 'jwk');
const xPkKeyObject = CryptoHelper.edPkToX25519Pk(publicKey, 'keyObject');

// convert Key Type
const obj2JWK = CryptoHelper.keyObject2JWK(xPkKeyObject as KeyObject);
const key2Jwk = CryptoHelper.key2JWK('X25519', xPkU8a as Uint8Array);
const jwk2Key = CryptoHelper.jwk2Key(xPkJwk as PublicJwk_ED).publicKey;
const jwk2Obj = CryptoHelper.jwk2KeyObject(xPkJwk as PublicJwk_ED, 'public');
```

---

### ECDH-ES (diffieHellman)

```ts
const verifier = await InfraSS58.createNewSS58DIDSet('space');
const holder = await InfraSS58.createNewSS58DIDSet('space');
const verifierX25519KeyPair = CryptoHelper.edToX25519KeyPair(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), hexToU8a(verifier.seed));
const holderX25519KeyPair = CryptoHelper.edToX25519KeyPair(hexToU8a(holder.publicKey.toJSON()['Ed25519']), hexToU8a(holder.seed));

const { publicKey: epk, privateKey: esk } = CryptoHelper.generateX25519KeyPairObject();
const verifierSecretUsingESK = CryptoHelper.jwkToEcdhesKeypair('X25519', holderX25519KeyPair.publicKeyJWK, esk);
const holderSecretUsingEPK = CryptoHelper.jwkToEcdhesKeypair('X25519', epk, holderX25519KeyPair.privateKeyJWK);

const verifierDIDSharedKey = CryptoHelper.jwkToEcdhesKeypair('X25519', holderX25519KeyPair.publicKeyJWK, verifierX25519KeyPair.privateKeyJWK);
const holderDIDSharedKey = CryptoHelper.jwkToEcdhesKeypair('X25519', verifierX25519KeyPair.publicKeyJWK, holderX25519KeyPair.privateKeyJWK);
```

---

### Derived Key(SLIP-0010 implementation)

- according to the https://github.com/satoshilabs/slips/blob/master/slip-0010.md
- example is 1 depth of testvector 1

```ts
const seed = '0x000102030405060708090a0b0c0d0e0f';
const mk = await DerivedEd25519Key.getMasterKey(seed);
// expect(mk.path).toEqual('m');
// expect(u8aToHex(mk.chainCode)).toEqual('0x90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb');
// expect(u8aToHex(mk.sk)).toEqual('0x2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7');
// expect(u8aToHex(mk.pk)).toEqual('0xa4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed');

const dk = await DerivedEd25519Key.getDeriveKey(mk.sk, mk.chainCode, mk.path, 0x80000000);
// expect(dk.path).toEqual('m/0h');
// expect(u8aToHex(dk.chainCode)).toEqual('0x8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69');
// expect(u8aToHex(dk.sk)).toEqual('0x68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3');
// expect(u8aToHex(dk.pk)).toEqual('0x8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c');
```

---

<!-- _class: lead -->

# End of Document

<!--footer: "" -->
