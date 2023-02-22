# (_need update_)Infra SS58 DID Javascript Library

- Infra DID Method Spec

  - https://github.com/InfraBlockchain/infra-did-method-specs/blob/main/docs/Infra-DID-method-spec.md

- Infra DID Resolver (DIF javascript universal resolver compatible)

  - https://github.com/InfraBlockchain/infra-did-resolver

- Infra DID Substrate Node

  - https://github.com/InfraBlockchain/infra-did-substrate

Feature provided by `infra-did-js/infra-SS58` library

- Infra SS58 DID Creation(SR25519, ED25519)
- Set/Get account keyPair
- Register/Unregister DID on chain
- Update/Remove DID attributes (service endpoint, controller DID)
- Update/Remove public key DID
- Set attestations claim
- Get Documents of DID(resolve)
- BBS+ KeyPair & public key Creation
- Add/Remove/Get BBS+ public key
- Add/Remove/Get BBS+ Params

## Infra SS58 DID API Configuration

```javascript
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

### Infra DID Creation

```javascript
DIDSet = await InfraSS58DID.createNewSS58DIDSet(
  networkId,
  CRYPTO_INFO.SR25519 // or CRYPTO_INFO.ED25519
)
console.log({ DIDSet })
```

```javascript
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

## Run test and see [ss58-test.ts](./src/__tests__/ss58-test.ts) for more information

```
yarn test ss58
```

**note** : When running the test for the first time, it takes a lot of time because jest transforms all SS58 related modules.
