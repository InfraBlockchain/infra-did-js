import "@babel/polyfill"
import b58 from 'bs58';
import { ApiPromise, Keyring, WsProvider } from '@polkadot/api';
import { HttpProvider } from '@polkadot/rpc-provider';
import { u8aToString, hexToU8a, u8aToHex } from '@polkadot/util';
import {
  randomAsHex,
  encodeAddress,
  mnemonicGenerate,
  mnemonicToMiniSecret,
  cryptoWaitReady,
  decodeAddress,
} from '@polkadot/util-crypto';

import { BTreeSet } from '@polkadot/types';
import { Codec } from '@polkadot/types-codec/types';
import { KeyringPair } from '@polkadot/keyring/types'; // eslint-disable-line
import { initializeWasm, KeypairG2, SignatureParamsG1 } from '@docknetwork/crypto-wasm-ts';
import typesBundle from '@docknetwork/node-types';

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
export const ATTESTS_IRI = 'https://rdf.dock.io/alpha/2021#attestsDocumentContents';
export const CRYPTO_INFO = {
  SR25519: {
    CRYPTO_TYPE: 'sr25519',
    KEY_TYPE: 'Sr25519VerificationKey2020',
    SIG_TYPE: 'Sr25519'
  },
  ED25519: {
    CRYPTO_TYPE: 'ed25519',
    KEY_TYPE: 'Ed25519VerificationKey2018',
    SIG_TYPE: 'Ed25519'
  }
} as const
export type CRYPTO_INFO = typeof CRYPTO_INFO[keyof typeof CRYPTO_INFO]
export type CRYPTO_TYPE = typeof CRYPTO_INFO.ED25519.CRYPTO_TYPE | typeof CRYPTO_INFO.SR25519.CRYPTO_TYPE
export type KEY_TYPE = typeof CRYPTO_INFO.ED25519.KEY_TYPE | typeof CRYPTO_INFO.SR25519.KEY_TYPE
export type SIG_TYPE = typeof CRYPTO_INFO.ED25519.SIG_TYPE | typeof CRYPTO_INFO.SR25519.SIG_TYPE

type HexString = `0x${string}`;

export interface IConfig {
  did: string;
  mnemonic?: string;
  seed?: HexString;
  address: string;
  cryptoInfo?: CRYPTO_INFO;
  verRels?: VerificationRelationship;
}

export interface DIDSet {
  did: string;
  seed: HexString;
  publicKey: PublicKey;
  verRels: VerificationRelationship;
  cryptoInfo: CRYPTO_INFO;
  didKey: DidKey;
  keyPair: KeyringPair;
}
interface BBSPlus_PublicKey {
  bytes: HexString,
  curveType: 'Bls12381',
  paramsRef?: [HexString, any],
}

export class PublicKey {
  constructor(private value: HexString, private sigType: SIG_TYPE = CRYPTO_INFO.SR25519.SIG_TYPE) {
    this.value = value;
    this.sigType = sigType;
  }
  static fromKeyringPair(pair: KeyringPair) {
    const [k,] = Object.entries(CRYPTO_INFO).find(([k, v]) => v.CRYPTO_TYPE === pair.type);
    return new this(u8aToHex(pair.publicKey), CRYPTO_INFO[k].SIG_TYPE);
  }

  toJSON() {
    return {
      [this.sigType]: this.value,
    };
  }
}


export class DidKey {
  constructor(private publicKey: PublicKey, private verRels: VerificationRelationship = undefined) {
    this.publicKey = publicKey;
    this.verRels = verRels !== undefined ? verRels : new VerificationRelationship();
  }
  toJSON() {
    return {
      publicKey: this.publicKey.toJSON(),
      verRels: this.verRels.value,
    };
  }
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

// eslint-disable-next-line no-bitwise
export class VerificationRelationship {
  constructor(private _value = 0) {}
  get value() { return this._value }
  setAuthentication() { this._value |= 0b0001 }
  setAssertion() { this._value |= 0b0010 }
  setCapabilityInvocation() { this._value |= 0b0100 }
  setKeyAgreement() { this._value |= 0b1000 }
  setAllSigning() { this._value |= 0b0111 }
  isAuthentication() { return !!(this._value & 0b0001) }
  isAssertion() { return !!(this._value & 0b0010) }
  isCapabilityInvocation() { return !!(this._value & 0b0100) }
  isKeyAgreement() { return !!(this._value & 0b1000) }
}
export class ServiceEndpointType {
  constructor(private _value = 0) {}
  get value() { return this._value }
  setLinkedDomains() {
    // eslint-disable-next-line no-bitwise
    this._value |= 0b0001;
  }
}

export default class InfraSS58DID {
  private static instance: InfraSS58DID

  private api;
  private verRels: VerificationRelationship;
  private seed: HexString;
  private address: string;
  private account: KeyringPair;
  private cryptoInfo: CRYPTO_INFO;
  private keyPairs: KeyringPair[];
  private publicKey: PublicKey;
  private didKey: DidKey;
  private did: string;
  private keyringModule: Keyring;
  get isConnected() {
    return this.api && this.api.isConnected || false;
  }
  setAccount(account: KeyringPair) {
    this.account = account
  }
  getAccount() {
    return this.account;
  }
  private constructor() {}


  static async createAsync(conf: IConfig): Promise<InfraSS58DID> {
    return await new InfraSS58DID().init(conf)
  }

  static async createNewSS58DIDSet(
    cryptoInfo: CRYPTO_INFO = CRYPTO_INFO.SR25519,
    verRels: VerificationRelationship =
      new VerificationRelationship(),
  ): Promise<DIDSet> {
    const hexId = randomAsHex(INFRA_DID_BYTE_SIZE);
    const ss58Id = encodeAddress(hexId);
    const did = `${INFRA_DID_QUALIFIER}${ss58Id}`;

    const seed = u8aToHex(mnemonicToMiniSecret(mnemonicGenerate()));
    const keyringModule = new Keyring({ type: cryptoInfo.CRYPTO_TYPE || 'sr25519' });
    await cryptoWaitReady();
    const keyPair: KeyringPair = keyringModule.addFromUri(seed, undefined, cryptoInfo.CRYPTO_TYPE);
    const publicKey = PublicKey.fromKeyringPair(keyPair);
    const didKey: DidKey = new DidKey(publicKey, verRels);
    return { did, didKey, keyPair, publicKey, seed, verRels, cryptoInfo };
  }
  static validateInfraSS58DID(infraSS58DID: string): boolean {
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

  private async init(conf: IConfig) {
    if (this.api) {
      if (this.api.isConnected) {
        throw new Error('API is already connected');
      } else {
        await this.disconnect();
      }
    }

    this.did = conf.did;
    this.cryptoInfo = conf.cryptoInfo ?? CRYPTO_INFO.SR25519;
    this.verRels = conf.verRels || new VerificationRelationship()

    this.address = conf.address || this.address;
    // check secure protocol 
    // if (this.address && (
    //   this.address.indexOf('wss://') === -1 && this.address.indexOf('https://') === -1
    // )) {
    //   console.warn(`WARNING: Using non-secure endpoint: ${this.address}`);
    // }
    const isWebsocket = this.address && this.address.indexOf('http') === -1;
    const provider = isWebsocket ? new WsProvider(this.address) : new HttpProvider(this.address);

    const apiOptions = {
      provider,
      rpc: {},
      typesBundle: typesBundle,
    };

    this.api = await ApiPromise.create(apiOptions);

    await cryptoWaitReady();
    this.keyringModule = new Keyring({ type: this.cryptoInfo.CRYPTO_TYPE || 'sr25519' });


    this.keyPairs = this.keyPairs ?? [];

    if (conf.mnemonic) {
      this.seed = u8aToHex(mnemonicToMiniSecret(conf.mnemonic));
    } else if (conf.seed) {
      this.seed = conf.seed;
    } else {
      this.seed = randomAsHex(INFRA_DID_BYTE_SIZE);
    }

    this.keyPairs.push(this.keyringModule.addFromUri(this.seed, undefined, this.cryptoInfo.CRYPTO_TYPE));
    this.publicKey = PublicKey.fromKeyringPair(this.keyPairs[0]);

    this.didKey = new DidKey(this.publicKey, this.verRels);

    await initializeWasm();
    return this
  }
  private static didToHex(did): HexString {
    return u8aToHex(decodeAddress(did.slice(INFRA_DID_QUALIFIER.length)));
  }
  private didToHex(did): HexString {
    return u8aToHex(decodeAddress(did.slice(INFRA_DID_QUALIFIER.length)));
  }
  private async getOnchainDIDDetail(hexDid: HexString): Promise<{
    nonce: number,
    lastKeyId: number,
    activeControllerKeys: number,
    activeControllers: number
  }> {
    try {
      const resp = await this.api.query.didModule.dids(hexDid)
      if (resp.isNone) { throw new Error("did not exist at onChain") }
      const didDetail = resp.unwrap().asOnChain;
      const data = didDetail.data || didDetail;

      return {
        nonce: didDetail.nonce.toNumber(),
        lastKeyId: data.lastKeyId.toNumber(),
        activeControllerKeys: data.activeControllerKeys.toNumber(),
        activeControllers: data.activeControllers.toNumber(),
      };
    } catch (e) { throw e }
  }

  private async signAndSend(extrinsic, waitForFinalization = true, params = {}) {
    const signedExtrinsic = await extrinsic.signAsync(this.account, params)
    return this.send(signedExtrinsic, waitForFinalization);
  }

  private async send(extrinsic, waitForFinalization = true) {
    const sendPromise = new Promise((resolve, reject) => {
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
          .catch((error) => { reject(error) })
          .then((unsub) => { unsubFunc = unsub });
      } catch (error) { reject(error) }
      return this;
    });
    return await sendPromise;
  }

  async getAttests(hexId) {
    const attests = await this.api.query.attest.attestations(hexId);
    return attests.iri.isSome
      ? u8aToString(hexToU8a(attests.iri.toString()))
      : null;
  }

  async getDocument({ getBbsPlusSigKeys = true } = {}) {
    const hexId = this.didToHex(this.did);
    let didDetails = await this.getOnchainDIDDetail(hexId);
    const ATTESTS_IRI = await this.getAttests(hexId);
    const id = (this.did === hexId) ? `${INFRA_DID_QUALIFIER}${encodeAddress(hexId)}` : this.did;

    const controllers = [];
    if (didDetails.activeControllers > 0) {
      const cnts = await this.api.query.didModule.didControllers.entries(hexId);
      cnts.forEach(([key, value]) => {
        if (value.isSome) {
          const [controlled, controller] = key.toHuman();
          if (controlled !== hexId) {
            throw new Error(`Controlled DID ${controlled[0]} was found to be different than queried DID ${hexId}`);
          }
          controllers.push(controller);
        }
      });
    }

    const serviceEndpoints = [];
    const sps = await this.api.query.didModule.didServiceEndpoints.entries(hexId);
    sps.forEach(([key, value]) => {
      if (value.isSome) {
        const sp = value.unwrap();
        // eslint-disable-next-line no-underscore-dangle
        const [d, spId] = key.args;
        // eslint-disable-next-line no-underscore-dangle
        const d_ = u8aToHex(d);
        if (d_ !== hexId) {
          throw new Error(`DID ${d_} was found to be different than queried DID ${hexId}`);
        }
        serviceEndpoints.push([spId, sp]);
      }
    });

    const keys = [];
    const assertion = [];
    const authn = [];
    const capInv = [];
    const keyAgr = [];
    if (didDetails.lastKeyId > 0) {
      const dks = await this.api.query.didModule.didKeys.entries(hexId);
      dks.forEach(([key, value]) => {
        if (value.isSome) {
          const dk = value.unwrap();
          // eslint-disable-next-line no-underscore-dangle
          const [d, i] = key.args;
          // eslint-disable-next-line no-underscore-dangle
          const d_ = u8aToHex(d);
          if (d_ !== hexId) {
            throw new Error(`DID ${d_} was found to be different than queried DID ${hexId}`);
          }
          const index = i.toNumber();
          const pk = dk.publicKey;
          let publicKeyRaw;
          let typ;
          if (pk.isSr25519) {
            typ = 'Sr25519VerificationKey2020';
            publicKeyRaw = pk.asSr25519.value;
          } else if (pk.isEd25519) {
            typ = 'Ed25519VerificationKey2018';
            publicKeyRaw = pk.asEd25519.value;
          } else {
            throw new Error(`Cannot parse public key ${pk}`);
          }
          keys.push([index, typ, publicKeyRaw]);
          const vr = new VerificationRelationship(dk.verRels.toNumber());
          if (vr.isAuthentication()) {
            authn.push(index);
          }
          if (vr.isAssertion()) {
            assertion.push(index);
          }
          if (vr.isCapabilityInvocation()) {
            capInv.push(index);
          }
          if (vr.isKeyAgreement()) {
            keyAgr.push(index);
          }
        }
      });
    }

    if (getBbsPlusSigKeys === true) {
      const { lastKeyId } = didDetails;
      if (lastKeyId > keys.length) {
        const possibleBbsPlusKeyIds = new Set();
        for (let i = 1; i <= lastKeyId; i++) {
          possibleBbsPlusKeyIds.add(i);
        }
        for (const [i] of keys) {
          possibleBbsPlusKeyIds.delete(i);
        }

        const queryKeys = [];
        for (const k of possibleBbsPlusKeyIds) {
          queryKeys.push([hexId, k]);
        }
        const resp = await this.api.query.bbsPlus.bbsPlusKeys.multi(queryKeys);
        function createPublicKeyObjFromChainResponse(pk) {
          const pkObj = {
            bytes: u8aToHex(pk.bytes),
            curveType: null,
            paramsRef: null,
          };
          if (pk.curveType.isBls12381) {
            pkObj.curveType = 'Bls12381';
          }
          if (pk.paramsRef.isSome) {
            const pr = pk.paramsRef.unwrap();
            pkObj.paramsRef = [u8aToHex(pr[0]), pr[1].toNumber()];
          } else {
            pkObj.paramsRef = null;
          }
          return pkObj;
        }
        let currentIter = 0;
        for (const r of resp) {
          // The gaps in `keyId` might correspond to removed keys
          if (r.isSome) {
            // Don't care about signature params for now
            const pkObj = createPublicKeyObjFromChainResponse(r.unwrap());
            if (pkObj.curveType !== 'Bls12381') {
              throw new Error(`Curve type should have been Bls12381 but was ${pkObj.curveType}`);
            }
            const keyIndex = queryKeys[currentIter][1];
            keys.push([keyIndex, 'Bls12381G2VerificationKeyDock2022', hexToU8a(pkObj.bytes)]);
            assertion.push(keyIndex);
          }
          currentIter++;
        }
      }
    }

    keys.sort((a, b) => a[0] - b[0]);
    assertion.sort();
    authn.sort();
    capInv.sort();
    keyAgr.sort();

    const verificationMethod = keys.map(([index, typ, publicKeyRaw]) => ({
      id: `${id}#keys-${index}`,
      type: typ,
      controller: id,
      publicKeyBase58: b58.encode(publicKeyRaw),
    }));
    const assertionMethod = assertion.map((i) => `${id}#keys-${i}`);
    const authentication = authn.map((i) => `${id}#keys-${i}`);
    const capabilityInvocation = capInv.map((i) => `${id}#keys-${i}`);
    const keyAgreement = keyAgr.map((i) => `${id}#keys-${i}`);
    let service = [];
    if (serviceEndpoints.length > 0) {
      const decoder = new TextDecoder();
      service = serviceEndpoints.map(([spId, sp]) => {
        const spType = sp.types.toNumber();
        if (spType !== 1) {
          throw new Error(
            `Only "LinkedDomains" supported as service endpoint type for now but found ${spType}`,
          );
        }
        return {
          id: decoder.decode(spId),
          type: 'LinkedDomains',
          serviceEndpoint: sp.origins.map((o) => decoder.decode(o)),
        };
      });
    }
    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id,
      controller: controllers.map((c) => `${INFRA_DID_QUALIFIER}${encodeAddress(c)}`),
      publicKey: verificationMethod,
      authentication,
      assertionMethod,
      keyAgreement,
      capabilityInvocation,
      ATTESTS_IRI,
      service,
    };
  }

  async disconnect() {
    if (this.api) {
      if (this.api.isConnected) {
        await this.api.disconnect();
      }
      delete this.api;
    }
  }

  async registerOnChain() {
    try {
      const hexId: unknown = this.didToHex(this.did)
      const didKeys = [this.didKey].map((d) => d.toJSON());
      const controllers = new BTreeSet(undefined, undefined, undefined)
      controllers.add(hexId as Codec)
      const tx = await this.api.tx.didModule.newOnchain(hexId, didKeys, controllers);
      return this.signAndSend(tx, false, {});
    } catch (e) { throw e }
  }

  async removeOnChain() {
    try {
      const hexDID = this.didToHex(this.did)
      const didDetail = await this.getOnchainDIDDetail(hexDID);
      const didRemoval = { did: hexDID, nonce: didDetail.nonce + 1 };

      const stateMessage = this.api.createType('StateChange', { 'DidRemoval': didRemoval }).toU8a();
      const controllerDIDSig = {
        did: hexDID, // controllerHexDid
        keyId: 1,
        sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
      }

      const tx = await this.api.tx.didModule.removeOnchainDid(didRemoval, controllerDIDSig);
      return this.signAndSend(tx, false, {});
    } catch (e) { throw e }
  }
  async addKeys(didKeys: DidKey[]) {
    const hexDID = this.didToHex(this.did)
    const didDetail = await this.getOnchainDIDDetail(hexDID);
    const keys = didKeys.map((d) => d.toJSON());
    const AddKeys = { did: hexDID, keys, nonce: didDetail.nonce + 1 };

    const stateMessage = this.api.createType('StateChange', { AddKeys }).toU8a();
    const controllerDIDSig = {
      did: hexDID, // controllerHexDid
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }

    const tx = await this.api.tx.didModule.addKeys(AddKeys, controllerDIDSig)
    return await this.signAndSend(tx, false, {})
  }
  async removeKeys(...keyIds: number[]) {
    const hexDID = this.didToHex(this.did)
    const didDetail = await this.getOnchainDIDDetail(hexDID);
    const keys = new BTreeSet(undefined, undefined, undefined);
    keyIds.forEach((keyId: unknown) => {
      keys.add(keyId as Codec);
    });

    const RemoveKeys = { did: hexDID, keys, nonce: didDetail.nonce + 1 };
    const stateMessage = this.api.createType('StateChange', { RemoveKeys }).toU8a();
    const controllerDIDSig = {
      did: hexDID, // controllerHexDid
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }

    const tx = await this.api.tx.didModule.removeKeys(RemoveKeys, controllerDIDSig)
    return await this.signAndSend(tx, false, {})
  }

  async addController(controllerDIDs: string[]) {
    const hexDID = this.didToHex(this.did)
    const didDetail = await this.getOnchainDIDDetail(hexDID);
    const controllers = new BTreeSet(undefined, undefined, undefined);
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = this.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });

    const AddControllers = { did: hexDID, controllers, nonce: didDetail.nonce + 1 };
    const stateMessage = this.api.createType('StateChange', { AddControllers }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }
    const tx = this.api.tx.didModule.addControllers(AddControllers, controllerDIDSig);
    return await this.signAndSend(tx, false, {});
  }

  async removeControllers(controllerDIDs: string[]) {
    const hexDID = this.didToHex(this.did)
    const didDetail = await this.getOnchainDIDDetail(hexDID);
    const controllers = new BTreeSet(undefined, undefined, undefined);
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = this.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });

    const RemoveControllers = { did: hexDID, controllers, nonce: didDetail.nonce + 1 };
    const stateMessage = this.api.createType('StateChange', { RemoveControllers }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }
    const tx = this.api.tx.didModule.removeControllers(RemoveControllers, controllerDIDSig);
    return await this.signAndSend(tx, false, {});
  }
  async addServiceEndpoint(
    endpointType?: ServiceEndpointType,
    originsTexts: string[] = ['https://foo.example.com'],
    endpointIdText?: string,
  ) {
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    if (!endpointType) {
      endpointType = new ServiceEndpointType()
      endpointType.setLinkedDomains()
    }
    const spId = u8aToHex(encoder.encode(endpointIdText));
    const origins = originsTexts.map((u) => u8aToHex(encoder.encode(u)));
    const hexDID = this.didToHex(this.did)
    const didDetail = await this.getOnchainDIDDetail(hexDID);

    const AddServiceEndpoint = {
      did: hexDID,
      id: spId,
      endpoint: { types: endpointType.value, origins },
      nonce: didDetail.nonce + 1,
    };
    const stateMessage = this.api.createType('StateChange', { AddServiceEndpoint }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }
    const tx = this.api.tx.didModule.addServiceEndpoint(AddServiceEndpoint, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }
  async removeServiceEndpoint(endpointIdText?: string) {
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    const spId = u8aToHex(encoder.encode(endpointIdText));
    const hexDID = this.didToHex(this.did)
    const didDetail = await this.getOnchainDIDDetail(hexDID);

    const RemoveServiceEndpoint = { did: hexDID, id: spId, nonce: didDetail.nonce + 1, };

    const stateMessage = this.api.createType('StateChange', { RemoveServiceEndpoint }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }
    const tx = this.api.tx.didModule.removeServiceEndpoint(RemoveServiceEndpoint, controllerDIDSig);


    return this.signAndSend(tx, false, {});
  }
  async getServiceEndpoint(endpointIdText?: string,) {
    const hexDID = this.didToHex(this.did);
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    const spId = u8aToHex(encoder.encode(endpointIdText));
    let resp = await this.api.query.didModule.didServiceEndpoints(hexDID, spId,);
    if (resp.isNone) {
      throw new Error(
        `No service endpoint found for did ${this.did} and with id ${endpointIdText}`,
      );
    }
    resp = resp.unwrap();
    return {
      type: new ServiceEndpointType(resp.types.toNumber()),
      origins: resp.origins.map((origin) => u8aToHex(origin)),
    };
  }
  async isController(controllerDID: string) {
    const controlledHexId = this.didToHex(this.did);
    const controllerHexId = this.didToHex(controllerDID);
    const resp = await this.api.query.didModule.didControllers(
      controlledHexId,
      controllerHexId,
    );
    return resp.isSome;
  }
  async setClaim(priority: number, iri: string) {
    const encoder = new TextEncoder();
    const hexDID = this.didToHex(this.did);
    const didDetail = await this.getOnchainDIDDetail(hexDID);
    const SetAttestationClaim = {
      attest: {
        priority, //: encoder.encode(priority),
        iri: u8aToHex(encoder.encode(iri)),
      },
      nonce: didDetail.nonce + 1,
    };
    const stateMessage = this.api.createType('StateChange', { SetAttestationClaim }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }
    const tx = this.api.tx.attest.setClaim(SetAttestationClaim, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }



  //--------- bbs+ module
  static BBSPlus_changeSigParamMessageCounter(sigParam: SignatureParamsG1, messageCounter: number): SignatureParamsG1 {
    return sigParam.adapt(messageCounter)
  }
  static BBSPlus_createSigParamsWithLabel(messageCounter: number, label?: string): SignatureParamsG1 {
    return label ?
      SignatureParamsG1.generate(messageCounter, hexToU8a(label)) :
      SignatureParamsG1.generate(messageCounter)
  }

  async BBSPlus_createSigParamsByDID(paramCounter: number)
    : Promise<SignatureParamsG1> {
    const queriedParams = await this.BBSPlus_getParams(paramCounter);
    const params1Val = SignatureParamsG1.valueFromBytes(hexToU8a(queriedParams.bytes));
    const sigParam = await new SignatureParamsG1(params1Val, hexToU8a(queriedParams.label));
    return sigParam;
  }

  static BBSPlus_createSigPublicKey(g1SigParams: SignatureParamsG1, params = undefined): BBSPlus_PublicKey {
    // params= [did, paramCounter]
    let keypair = KeypairG2.generate(g1SigParams);
    const bytes = u8aToHex(keypair.publicKey.bytes);

    let paramsRef = undefined;
    if (params) {
      if (!(typeof params === 'object' && params instanceof Array && params.length === 2)) {
        throw new Error('Reference should be an array of 2 items');
      }
      if (typeof params[1] !== 'number') {
        throw new Error(`Second item of reference should be a number but was ${params[1]}`);
      }
      const hexDID = InfraSS58DID.didToHex(params[0])
      paramsRef = [hexDID, params[1]]
    }
    return { bytes, paramsRef, curveType: 'Bls12381' };
  }


  private async BBSPlus_getParamsByHexDid(hexDid, counter) {
    const resp = await this.api.query.bbsPlus.bbsPlusParams(hexDid, counter);
    if (resp.isSome) {
      const params = resp.unwrap()
      return {
        bytes: u8aToHex(params.bytes),
        curveType: 'Bls12381',
        label: params.label.isSome ? u8aToHex(params.label.unwrap()) : null
      }
    }
    return null;
  }

  private async BBSPlus_getPublicKeyByHexDid(hexDid, keyId, withParams = false) {
    const resp = await this.api.query.bbsPlus.bbsPlusKeys(hexDid, keyId);
    if (resp.isSome) {
      const pk = resp.unwrap();
      let paramsRef = null
      if (pk.paramsRef.isSome) {
        const pr = pk.paramsRef.unwrap();
        paramsRef = [u8aToHex(pr[0]), pr[1].toNumber()]
      }
      const pkObj = {
        bytes: u8aToHex(pk.bytes),
        curveType: 'Bls12381',
        paramsRef,
        params: null,
      };
      if (withParams) {
        if (pkObj.paramsRef === null) {
          throw new Error('No reference to parameters for the public key');
        } else {
          const params = await this.BBSPlus_getParamsByHexDid(pkObj.paramsRef[0], pkObj.paramsRef[1]);
          if (params === null) {
            throw new Error(`Parameters with reference (${pkObj.paramsRef[0]}, ${pkObj.paramsRef[1]}) not found on chain`);
          }
          pkObj.params = params;
        }
      }
      return pkObj;
    }
    return null;
  }


  async BBSPlus_addPublicKey(publicKey: BBSPlus_PublicKey) {
    const hexDID = this.didToHex(this.did);
    const didDetail = await this.getOnchainDIDDetail(hexDID);

    const AddBBSPlusPublicKey = { key: publicKey, did: hexDID, nonce: didDetail.nonce + 1 };
    const stateMessage = this.api.createType('StateChange', { AddBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }

    const tx = await this.api.tx.bbsPlus.addPublicKey(AddBBSPlusPublicKey, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }
  async BBSPlus_removePublicKey(removeKeyId) {
    const hexDID = this.didToHex(this.did);
    const didDetail = await this.getOnchainDIDDetail(hexDID);

    const RemoveBBSPlusPublicKey = { keyRef: [hexDID, removeKeyId], did: hexDID, nonce: didDetail.nonce + 1 };
    const stateMessage = this.api.createType('StateChange', { RemoveBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }
    const tx = await this.api.tx.bbsPlus.removePublicKey(RemoveBBSPlusPublicKey, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async BBSPlus_getPublicKey(keyId, withParams = false) {
    const hexId = this.didToHex(this.did);
    return this.BBSPlus_getPublicKeyByHexDid(hexId, keyId, withParams);
  }

  async BBSPlus_addParams(sigParam: SignatureParamsG1, label?: string) {
    const params = {
      bytes: u8aToHex(sigParam.toBytes()),
      curveType: 'Bls12381',
      label
    }
    const hexDID = this.didToHex(this.did);
    const didDetail = await this.getOnchainDIDDetail(hexDID);

    const AddBBSPlusParams = { params, nonce: didDetail.nonce + 1 };
    const stateMessage = this.api.createType('StateChange', { AddBBSPlusParams }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }
    const tx = await this.api.tx.bbsPlus.addParams(AddBBSPlusParams, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }
  async BBSPlus_removeParams(index) {
    const hexDID = this.didToHex(this.did);
    const didDetail = await this.getOnchainDIDDetail(hexDID);

    const RemoveBBSPlusParams = { paramsRef: [hexDID, index], nonce: didDetail.nonce + 1 };
    const stateMessage = this.api.createType('StateChange', { RemoveBBSPlusParams }).toU8a();
    const controllerDIDSig = {
      did: hexDID,
      keyId: 1,
      sig: { [this.cryptoInfo.SIG_TYPE]: u8aToHex(this.keyPairs[0].sign(stateMessage)) }
    }

    const tx = await this.api.tx.bbsPlus.removeParams(RemoveBBSPlusParams, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async BBSPlus_getParams(counter) {
    const hexId = this.didToHex(this.did);
    return await this.BBSPlus_getParamsByHexDid(hexId, counter);
  }

  async BBSPlus_getLastParamsWritten() {
    const hexId = this.didToHex(this.did);
    const counter = await this.api.query.bbsPlus.paramsCounter(hexId);
    if (counter < 1) return null
    return await this.BBSPlus_getParamsByHexDid(hexId, counter)
  }

  async BBSPlus_getAllParams() {
    const hexId = this.didToHex(this.did);

    const params = [];
    const counter = await this.api.query.bbsPlus.paramsCounter(hexId);
    if (counter > 0) {
      for (let i = 1; i <= counter; i++) {
        const param = await this.BBSPlus_getParamsByHexDid(hexId, i);
        if (param !== null) {
          params.push(param);
        }
      }
    }
    return params;
  }



}
