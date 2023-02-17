

import "@babel/polyfill"
import { ApiPromise, Keyring, WsProvider } from '@polkadot/api';
// import { ApiOptions } from '@polkadot/api/types';
import { HttpProvider } from '@polkadot/rpc-provider';
import { KeyringPair } from '@polkadot/keyring/types'; // eslint-disable-line
// import typesBundle from '@docknetwork/node-types';
import { u8aToHex } from '@polkadot/util';
import {
  randomAsHex,
  encodeAddress,
  mnemonicGenerate,
  mnemonicToMiniSecret,
  cryptoWaitReady,
  decodeAddress,
} from '@polkadot/util-crypto';


// import BlobModule from './modules/blob';
// import { DIDModule } from './modules/did';
// import RevocationModule from './modules/revocation';

// import BlobModule from './polkadot/dock/modules/blob';
// import { DIDModule } from './polkadot/dock/modules/did';
// import RevocationModule from './polkadot/dock/modules/revocation';

// import VerifiableCredential from './polkadot/dock/verifiable-credential';
// import VerifiablePresentation from './polkadot/dock/verifiable-presentation';
// import {
//   createRandomRegistryId, OneOfPolicy, buildDockCredentialStatus, getDockRevIdFromCredential,
// } from './polkadot/dock/utils/revocation';
// import Schema from './polkadot/dock/modules/schema';


const INFRA_DID_METHOD = 'infra';
const INFRA_DID_NETWORK_ID = '02';
const INFRA_DID_QUALIFIER = `did:${INFRA_DID_METHOD}:${INFRA_DID_NETWORK_ID}:`;
const INFRA_DID_BYTE_SIZE = 32;

export enum CRYPTO_TYPE {
  SR25519 = 'sr25519',
  ED25519 = 'ed25519',
};
type HexSeed = `0x${string}`;
export interface IConfig {
  did: string;
  mnemonic?: string;
  seed?: HexSeed;
  address: string;
  cryptoType?: CRYPTO_TYPE;
  verRels?: VerificationRelationship;
}
export interface DidKey {
  publicKey: string,
  verRels: VerificationRelationship;
}
export class ExtrinsicError extends Error {
  constructor(message, private method, private data, private status, private events) {
    super(message);
    this.name = 'ExtrinsicError';
  }
}
export function getExtrinsicError(data, typeDef, api) {
  let errorMsg = 'Extrinsic failed submission:';
  data.forEach((error) => {
    if (error.isModule) {
      try {
        const decoded = api.registry.findMetaError(error.asModule);
        const { docs, method, section } = decoded;
        errorMsg += `\n${section}.${method}: ${docs.join(' ')}`;
      } catch (e) {
        errorMsg += `\nError at module index: ${error.asModule.index} Error: ${error.asModule.error}`;
      }
    } else {
      const errorStr = error.toString();
      if (errorStr !== '0') {
        errorMsg += `\n${errorStr}`;
      }
    }
  });
  return errorMsg;
}

export class VerificationRelationship {
  value: number;
  constructor(value = 0) {
    this.value = value;
  }

  setAuthentication() {
    // eslint-disable-next-line no-bitwise
    this.value |= 0b0001;
  }

  setAssertion() {
    // eslint-disable-next-line no-bitwise
    this.value |= 0b0010;
  }

  setCapabilityInvocation() {
    // eslint-disable-next-line no-bitwise
    this.value |= 0b0100;
  }

  setKeyAgreement() {
    // eslint-disable-next-line no-bitwise
    this.value |= 0b1000;
  }

  setAllSigning() {
    // eslint-disable-next-line no-bitwise
    this.value |= 0b0111;
  }

  isAuthentication() {
    // eslint-disable-next-line no-bitwise
    return !!(this.value & 0b0001);
  }

  isAssertion() {
    // eslint-disable-next-line no-bitwise
    return !!(this.value & 0b0010);
  }

  isCapabilityInvocation() {
    // eslint-disable-next-line no-bitwise
    return !!(this.value & 0b0100);
  }

  isKeyAgreement() {
    // eslint-disable-next-line no-bitwise
    return !!(this.value & 0b1000);
  }
}

export default class InfraSS58DID {
  private api
  private verRels: VerificationRelationship;
  private seed: HexSeed;
  private address: string;
  private _account: KeyringPair;
  private cryptoType: CRYPTO_TYPE;
  private _keyPairs: KeyringPair[];
  private publicKey: string;
  private didKey: DidKey;
  private did: string;
  // private blobModule;
  // private didModule;
  // private revocationModule;
  private keyringModule: Keyring;
  get keyPairs() { return this._keyPairs }

  set account(account) {
    this._account = account;
  }
  get account() {
    return this._account;
  }
  get isConnected() {
    return this.api && this.api.isConnected || false;
  }
  getKeyDoc(id, type, keypairId = 1) {
    return {
      id: id || `${this.did}#keys-1`,
      controller: this.did,
      type,
      keypair: this._keyPairs[keypairId - 1],
    };
  }
  constructor(conf: IConfig) {
    this.init(conf).then(() => {
      this.did = conf.did;
      InfraSS58DID.validateInfraSS58DID(this.did);

      this.cryptoType = conf.cryptoType ?? CRYPTO_TYPE.SR25519;
      this.verRels = conf.verRels || new VerificationRelationship()
      this._keyPairs = this._keyPairs ?? [];

      if (conf.mnemonic) {
        this.seed = u8aToHex(mnemonicToMiniSecret(conf.mnemonic));
      } else if (conf.seed) {
        this.seed = conf.seed;
      } else {
        this.seed = randomAsHex(INFRA_DID_BYTE_SIZE);
      }

      this._keyPairs.push(this.keyringModule.addFromUri(this.seed, undefined, this.cryptoType));
      this.publicKey = u8aToHex(this._keyPairs[0].publicKey);
      this.didKey = { publicKey: this.publicKey, verRels: this.verRels };
    })
  }

  static async createNewSS58DIDSet(
    cryptoType: CRYPTO_TYPE = CRYPTO_TYPE.SR25519,
    verRels: VerificationRelationship =
      new VerificationRelationship(),
  ): Promise<{ did: string; seed: HexSeed; publicKey: string, verRels: VerificationRelationship; cryptoType: CRYPTO_TYPE; didKey: DidKey; keyPair: KeyringPair; }> {
    const hexId = randomAsHex(INFRA_DID_BYTE_SIZE);
    const ss58Id = encodeAddress(hexId);
    const did = `${INFRA_DID_QUALIFIER}${ss58Id}`;

    const seed = u8aToHex(mnemonicToMiniSecret(mnemonicGenerate()));
    const keyringModule = new Keyring({ type: cryptoType || 'sr25519' });
    await cryptoWaitReady();
    const keyPair: KeyringPair = keyringModule.addFromUri(seed, undefined, cryptoType);
    const didKey: DidKey = { publicKey: u8aToHex(keyPair.publicKey), verRels };
    return { did, didKey, keyPair, publicKey: didKey.publicKey, seed, verRels, cryptoType };
  }



  async init(conf: IConfig) {
    if (this.api) {
      if (this.api.isConnected) {
        throw new Error('API is already connected');
      } else {
        await this.disconnect();
      }
    }

    this.address = conf.address || this.address;
    if (this.address && (
      this.address.indexOf('wss://') === -1 && this.address.indexOf('https://') === -1
    )) {
      console.warn(`WARNING: Using non-secure endpoint: ${this.address}`);
    }
    const isWebsocket = this.address && this.address.indexOf('http') === -1;
    const provider = isWebsocket ? new WsProvider(this.address) : new HttpProvider(this.address);

    const apiOptions = {
      provider,
      // @ts-ignore: TS2322
      rpc,
      // typesBundle: typesBundle,
    };

    this.api = await ApiPromise.create(apiOptions);
    console.log(1)
    await cryptoWaitReady();
    this.keyringModule = new Keyring({ type: this.cryptoType || 'sr25519' });
    // this.blobModule = new BlobModule(this.api, this.signAndSend.bind(this));
    // this.didModule = new DIDModule(this.api, this.signAndSend.bind(this));
    // this.revocationModule = new RevocationModule(this.api, this.signAndSend.bind(this));

  }

  async disconnect() {
    if (this.api) {
      if (this.api.isConnected) {
        await this.api.disconnect();
      }
      delete this.api;
      // delete this.blobModule;
      // delete this.didModule;
      // delete this.revocationModule;
    }
  }

  static validateInfraSS58DID(infraSS58DID): boolean {
    const didSplit = infraSS58DID.split(':')
    if (didSplit.length !== 4) {
      throw new Error(`invalid infraSS58DID, needs network identifier part and id part (${infraSS58DID})`)
    }

    const regex = new RegExp(/^[5KL][1-9A-HJ-NP-Za-km-z]{47}$/);
    const matches = regex.exec(didSplit[3]);
    if (!matches) {
      throw new Error('The identifier must be 32 bytes and valid SS58 string');
    }
    return true
  }

  async removeOnChain() {
    // keypairs index: 0 -> keyid: 1
    // await this.didModule.remove(this.did, this.did, this._keyPairs[0], 1, undefined, false);

    const targetHexDid = u8aToHex(decodeAddress(this.did.slice(INFRA_DID_QUALIFIER.length)));
    const controllerHexDid = u8aToHex(decodeAddress(this.did.slice(INFRA_DID_QUALIFIER.length)));
    const nonce = (await this.api.query.didModule.dids(controllerHexDid).unwrap().asOnChain.nonce.toNumber()) + 1;
    const didRemoval = { did: targetHexDid, nonce };
    const serializedRemoval = this.api.createType('StateChange', { 'DidRemoval': didRemoval }).toU8a();
    const signature = { value: u8aToHex(this.keyPairs[0].sign(serializedRemoval)) }
    const sigType = this.keyPairs[0].type.replace(/^[a-z]/, char => char.toUpperCase());
    const didSig = { controllerHexDid, keyId: 1, sig: { [sigType]: signature.value } }

    const tx = await this.api.tx.didModule.removeOnchainDid(didRemoval, didSig);

    return this.signAndSend(tx, false, {});
  }





  async signExtrinsic(extrinsic, params = {}) {
    return extrinsic.signAsync(this._account, params);
  }
  async signAndSend(extrinsic, waitForFinalization = true, params = {}) {
    const signedExtrinsic = await this.signExtrinsic(extrinsic, params);
    return this.send(signedExtrinsic, waitForFinalization);
  }
  async send(extrinsic, waitForFinalization = true) {
    const promise = new Promise((resolve, reject) => {
      try {
        let unsubFunc = () => {};
        return extrinsic
          .send((extrResult) => {
            const { events = [], status } = extrResult;
            for (let i = 0; i < events.length; i++) {
              const {
                event: {
                  data, method, typeDef,
                },
              } = events[i];
              if (method === 'ExtrinsicFailed' || method === 'BatchInterrupted') {
                const errorMsg = getExtrinsicError(data, typeDef, this.api);
                const error = new ExtrinsicError(errorMsg, method, data, status, events);
                reject(error);
                return error;
              }
            }
            if ((waitForFinalization && status.isFinalized) || (!waitForFinalization && status.isInBlock)) {
              unsubFunc();
              resolve(extrResult);
            }
            return extrResult;
          })
          .catch((error) => {
            reject(error);
          })
          .then((unsub) => {
            unsubFunc = unsub;
          });
      } catch (error) {
        reject(error);
      }
      return this;
    });
    return await promise;
  }



  signVC() {}
  verifyVC() {}

  //   static async wrapper<T>(cb): Promise<Awaited<T>> {
  //     return dock.init({ address: 'ws://localhost:9944' })
  //       .then(cb)
  //       .then((res: T) => { dock.disconnect(); return res })
  //   };
}


export interface IInfraDID {
  /** done*/
  /* TODO */
  /*! remove*/
  /*? need check */
  /** done: static. 신규 키 생성 ::: createNewSS58DIDAndKey*/
  createPubKeyDIDsecp256k1(networkId: string): { did: string, publicKey: string, privateKey: string };
  setAttributePubKeyDID(key: string, value: string): {};

  changeOwnerPubKeyDID(newOwnerPubKey: string): {};
  revokePubKeyDID(): {};
  clearPubKeyDID(): {};

  registerTrustedPubKeyDID(authorizer: string, didPubKey: string, properties: string): {};
  updateTrustedPubKeyDID(authorizer: string, didPubKey: string, properties: string): {};
  removeTrustedPubKeyDID(authorizer: string, didPubKey: string): {};

  getTrustedPubKeyDIDByAuthorizer(authorizer: string): {};
  getTrustedPubKeyDIDByTarget(didPubKey: string): {};
  getTrustedPubKeyDID(authorizer: string, didPubKey: string): {};

  // getJwtVcIssuer(): JwtVcIssuer;
  signJWT(payload: undefined, expiresIn: number): {};
  verifyJWT(jwt: undefined, resolver: undefined, audience: undefined): Promise<any>;
}

