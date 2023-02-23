# (_need update_)Infra SS58 DID Javascript Library

- Infra DID Method Spec

  - https://github.com/InfraBlockchain/infra-did-method-specs/blob/main/docs/Infra-DID-method-spec.md

- Infra DID Resolver (DIF ts universal resolver compatible)

  - https://github.com/InfraBlockchain/infra-did-resolver

- Infra DID Substrate Node

  - https://github.com/InfraBlockchain/infra-did-substrate

Feature provided by `infra-did-js/infra-SS58` library

- Infra SS58 DID Creation(SR25519, ED25519)
- Register/Unregister DID on chain
- Update/Remove DID attributes (service endpoint, controller DID, public key)
- Set attestations claim
- Get Documents of DID(resolve)
- BBS+ KeyPair & public key Creation
- Add/Remove/Get BBS+ public key
- Add/Remove/Get BBS+ Params

## Infra SS58 DID API Configuration

```ts
import InfraSS58DID, {cryptoWaitReady, Keyring, CRYPTO_INFO} from 'infra-did-js/infra-SS58'

await cryptoWaitReady()
const txfeePaterAccountKeyPair = (new Keyring({ type: 'sr25519' })).addFromUri('//Alice')
const confBlockchainNetwork = {
  networkId: '02',
  address: 'wss://polkadot.infrablockchain.com',
  txfeePayerAccountKeyPair,
  // or txfeePayerAccountSeed: 'TX_FEE_PAYER_ACCOUNT_SEED'
}
const conf = {
  ...confBlockchainNetwork,
  did: 'did:infra:02:5CRV5zBdAhBALnXiBSWZWjca3rSREBg87GJ6UY9i2A7y1rCs',
  controllerDID: 'did:infra:02:5HdJprb8NhaJsGASLBKGQ1bkKkvaZDaK1FxTbJRXNShFuqgY'
  controllerSeed: 'DID_CONTROLLER_SEED',
  // or controllerKeyPair: controllerKeyPair
}
const didApi = await InfraSS58DID.createAsync(conf)
```

## Infra SS58 DID Creation

```ts
DIDSet = await InfraSS58DID.createNewSS58DIDSet(
  networkId,
  CRYPTO_INFO.SR25519 // or CRYPTO_INFO.ED25519
)
console.log({ DIDSet })
```

```ts
{
  DIDSet: {
    did: 'did:infra:02:5CVYkrck83yR9McJEf7sdwq5eZaKhHUq5KVoieHR4iiuoXz2',
    didKey: DidKey {
      publicKey: [PublicKey],
      verRels: [VerificationRelationship]
    },
    keyPair: {
      address: [Getter],
      publicKey: [Getter],
      type: [Getter],
      sign: [Function: sign],
      toJson: [Function: toJson],
      verify: [Function: verify],
      ...
    },
    publicKey: PublicKey {
      value: '0x6a5e572022b8acaecd9b2857ac4ad4964cdfcc60dcf832eeca2d752a79b75634',
      sigType: 'Sr25519'
    },
    seed: '0x2ee2e47383c88dc07ecf860f54e5bce9c8f7d944c0b80dcb2c87abb4c9edd55c',
    verRels: VerificationRelationship { _value: 0 },
    cryptoInfo: {
      CRYPTO_TYPE: 'sr25519',
      KEY_TYPE: 'Sr25519VerificationKey2020',
      SIG_TYPE: 'Sr25519'
    }
  }
}
```

### Infra SS58 DID Format Validation

```ts
InfraSS58DID.validateInfraSS58DID(SOME_DID_STRING)
```

## OnCain DID

### Infra SS58 DID Register / unRegister OnChain

```ts
await didApi.registerOnchain()
await didApi.unregisterOnChain()
```

### Add Public key

```ts
await didApi.addPublicKeyByDIDKeys(SOME_DID_KEY)
```

### Remove Public key

```ts
await didApi.addPublicKeyByDIDKeys(DID_KEY_IDS)
```

### Add Controller DID

```ts
await didApi.addControllers(CONTROLLER_DID)
```

### Remove Controller DID

```ts
await didApi.removeControllers(CONTROLLER_DID)
```

### Add Service Endpoint

```ts
await didApi.addServiceEndpoint(SOME_SERVICE_ENDPOINT_URL)
```

### Remove Service Endpoint

```ts
await didApi.removeServiceEndpoint(SOME_SERVICE_ENDPOINT_URL)
```

### Set Attestation Claim

```ts
await didApi.setClaim(PRIORITY_NUMBER, CLAIM_IRI)
```

### Resolve DID Document(Temporary)

```ts
const didDocuments = await infraDID.getDocument()
console.log({ didDocuments })
```

```json
{
  "didDocuments": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:infra:02:5FXjDqDqjDE9Ywo78K9DqVLUmn4vqQ3hpLU8NNcJbFmCPSAs",
    "controller": [
      "did:infra:02:5FXjDqDqjDE9Ywo78K9DqVLUmn4vqQ3hpLU8NNcJbFmCPSAs"
    ],
    "publicKey": [
      {
        "id": "did:infra:02:5FXjDqDqjDE9Ywo78K9DqVLUmn4vqQ3hpLU8NNcJbFmCPSAs#keys-1",
        "type": "Sr25519VerificationKey2020",
        "controller": "did:infra:02:5FXjDqDqjDE9Ywo78K9DqVLUmn4vqQ3hpLU8NNcJbFmCPSAs",
        "publicKeyBase58": "4n7uzyggznG2AnoMh9L4JwgGRbgia9qQ44wLkwcqhNEg"
      }
    ],
    "authentication": [
      "did:infra:02:5FXjDqDqjDE9Ywo78K9DqVLUmn4vqQ3hpLU8NNcJbFmCPSAs#keys-1"
    ],
    "assertionMethod": [
      "did:infra:02:5FXjDqDqjDE9Ywo78K9DqVLUmn4vqQ3hpLU8NNcJbFmCPSAs#keys-1"
    ],
    "keyAgreement": [],
    "capabilityInvocation": [
      "did:infra:02:5FXjDqDqjDE9Ywo78K9DqVLUmn4vqQ3hpLU8NNcJbFmCPSAs#keys-1"
    ],
    "ATTESTS_IRI": null,
    "service": []
  }
}
```

## BBS+

### BBS+ SigSet Creation

```ts
const newSigSet = InfraSS58DID.BBSPlus_createNewSigSet(MESSAGE_COUNTER_NUMBER)
const sigSetByDID = await infraDID.BBSPlus_createNewSigSet(PARAM_COUNTER_NUMBER)
console.log({ newSigSet })
```

```js
{
  newSigSet: {
    sigParam: SignatureParamsG1 {
      value: {...},
      label: undefined
    },
    keyPair: KeypairG2 {
      sk: BBSPlusSecretKey { value: [Uint8Array] },
      pk: BBSPlusPublicKeyG2 { value: [Uint8Array] }
    },
    publicKey: {
      bytes: '0xe9f99021d89e072454bd13eeb8bf08343282d2a25a842be02315c342ede11019cdfc9c3dd97408595b56cda4abaf980014355d7de9da92122619c320618d1fd932b4a2219c087e7783beec0517261716c5a5fa10999f621ef308dc017656e598',
      paramsRef: undefined,
      curveType: 'Bls12381'
    },
    messageCounter: 10,
    label: undefined
  }
}
```

### Add BBS+ Params

```ts
const sigParam = InfraSS58DID.BBSPlus_createSigParamsWithLabel(
  MESSAGE_COUNTER_NUMBER,
  'some-param-label'
)
await infraDID.BBSPlus_addParams(sigParam)
```

### Get BBS+ Params

```ts
const param = await infraDID.BBSPlus_getParams(PARAM_COUNTER_NUMBER)
const lastParam = await infraDID.BBSPlus_getLastParamsWritten()
```

```js
{
  param: SignatureParamsG1 {
    value: {...},
    label: undefined
  }
}
```

### Remove BBS+ Params

```ts
await infraDID.BBSPlus_removeParams(PARAM_COUNTER_NUMBER)
```

### Add BBS+ Public Key

```ts
await infraDID.BBSPlus_addPublicKey(newSigSet.publicKey)
```

### GET BBS+ Public Key

```ts
const publicKey = await infraDID.BBSPlus_getPublicKey(KEY_ID_NUMBER)
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
await infraDID.BBSPlus_removePublicKey(KEY_ID_NUMBER)
```
