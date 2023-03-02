import { ApiPromise, Keyring, WsProvider } from '@polkadot/api';
import { HttpProvider } from '@polkadot/rpc-provider';
import { u8aToString, hexToU8a, u8aToHex } from '@polkadot/util';
import b58 from 'bs58';
import {
  encodeAddress,
  decodeAddress,
  mnemonicGenerate,
  mnemonicToMiniSecret,
  cryptoWaitReady,
  blake2AsHex
} from '@polkadot/util-crypto';
import { BTreeSet } from '@polkadot/types';
import { Codec } from '@polkadot/types-codec/types';
import { KeyringPair } from '@polkadot/keyring/types';
import typesBundle from '@docknetwork/node-types';
import { initializeWasm, KeypairG2, SignatureParamsG1 } from '@docknetwork/crypto-wasm-ts';
import VerifiableCredential from './infra-ss58-vc';
export { KeyringPair }

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
export type SIG_TYPE = typeof CRYPTO_INFO.ED25519.SIG_TYPE | typeof CRYPTO_INFO.SR25519.SIG_TYPE

export type HexString = `0x${string}`;

export interface IConfig {
  did: string;
  address: string;
  networkId: string;
  seed?: HexString;
  mnemonic?: string; //alter to seed
  controllerDID?: string;// same role as didOwnerPrivateKey
  controllerKeyPair?: KeyringPair; // same role as didOwnerPrivateKey
  controllerSeed?: HexString; // alter to controllerKeyPair
  txfeePayerAccountKeyPair?: KeyringPair, // same role as txfeePayerAccount
  txfeePayerAccountSeed?: HexString, // alter to txfeePayerAccountKeyPair
  cryptoInfo?: CRYPTO_INFO;
  verRels?: VerificationRelationship;
}

export interface DIDSet {
  did: string;
  seed: HexString;
  mnemonic: string;
  publicKey: PublicKey;
  verRels: VerificationRelationship;
  cryptoInfo: CRYPTO_INFO;
  didKey: DidKey;
  keyPair: KeyringPair;
}
export interface BBSPlus_SigSet {
  sigParam: SignatureParamsG1,
  keyPair: KeypairG2,
  publicKey: BBSPlus_PublicKey,
  paramCounter?: number,
  messageCounter?: number,
  label?: string
}
export interface BBSPlus_PublicKey {
  bytes: HexString,
  curveType: 'Bls12381',
  paramsRef?: [HexString, number],
  params?: any,
}
export interface BBSPlus_Params {
  bytes: HexString;
  curveType: 'Bls12381',
  label: string;
}
export class PublicKey {
  constructor(private value: HexString, private sigType: SIG_TYPE = CRYPTO_INFO.SR25519.SIG_TYPE) {
    this.value = value;
    this.sigType = sigType;
  }
  static fromKeyringPair(pair: KeyringPair): PublicKey {
    const [key,] = Object.entries(CRYPTO_INFO).find(([, value]) => value.CRYPTO_TYPE === pair.type);
    return new this(u8aToHex(pair.publicKey), CRYPTO_INFO[key].SIG_TYPE);
  }
  toJSON() {
    return {
      [this.sigType]: this.value,
    };
  }
}

export class DidKey {
  constructor(private publicKey: PublicKey, private verRels: VerificationRelationship = undefined) {
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
  constructor(private api, private typeDef, private method, private data, private status, private events) {
    super(ExtrinsicError.getErrorMsg(data, typeDef, api));
    this.name = 'ExtrinsicError';
  }
  static getErrorMsg(data, typeDef, api): string {
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

}

export class VerificationRelationship {
  constructor(private _value = 0b0000) {}
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
class InfraSS58 {
  private _api;
  get api() {
    return this._api;
  }
  protected set api(value) {
    this._api = value;
  }
  protected accountKeyPair
  protected constructor() {}
  protected static splitDID(did: string) {
    const splitDID = did.split(':')
    return {
      ss58ID: splitDID.pop(),
      qualifier: splitDID.join(':'),
    }
  }
  protected static didToHex(did: string): HexString {
    const { ss58ID } = InfraSS58DID.splitDID(did);
    return u8aToHex(decodeAddress(ss58ID));
  }

  protected static async getKeyPairFromSeed(seed: HexString, cryptoInfo: CRYPTO_INFO): Promise<KeyringPair> {
    const keyringModule = new Keyring({ type: cryptoInfo.CRYPTO_TYPE || CRYPTO_INFO.SR25519.CRYPTO_TYPE });
    await cryptoWaitReady();
    return keyringModule.addFromUri(seed, undefined, cryptoInfo.CRYPTO_TYPE);
  }
  static async getKeyPairFromUri(uri, cryptoInfo?: CRYPTO_INFO): Promise<KeyringPair> {
    const keyringModule = new Keyring({ type: cryptoInfo.CRYPTO_TYPE || CRYPTO_INFO.SR25519.CRYPTO_TYPE });
    await cryptoWaitReady();
    return keyringModule.addFromUri(uri);
  }
  protected static ss58addrToDID(networkId, addr) { return `did:infra:${networkId}:${addr}` }
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
  protected getSig(sigType, keyPair, stateMessage) {
    return { [sigType]: u8aToHex(keyPair.sign(stateMessage)) }
  }

  protected getDIDSig(did: string, sigType: SIG_TYPE, keyPair: KeyringPair, stateMessage, keyId = 1) {
    return {
      did: InfraSS58DID.didToHex(did),
      keyId,
      sig: this.getSig(sigType, keyPair, stateMessage)
    }
  }


  protected async signAndSend(extrinsic, waitForFinalization = true, params = {}) {
    // @ts-ignore
    params.nonce = await this.api.rpc.system.accountNextIndex(this.accountKeyPair.address);
    const signedExtrinsic = await extrinsic.signAsync(this.accountKeyPair, params)
    return this.send(signedExtrinsic, waitForFinalization);
  }

  protected async send(extrinsic, waitForFinalization = true) {
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
                const error = new ExtrinsicError(this.api, typeDef, method, data, status, events);
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

  async disconnect() {
    if (this.api) {
      if (this.api.isConnected) {
        await this.api.disconnect();
      }
      delete this.api;
    }
  }
  protected async getOnchainDIDDetail(hexDid: HexString): Promise<{
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
  protected async getNextNonce(hexDID: HexString): Promise<number> {
    return await this.getOnchainDIDDetail(hexDID).then(detail => detail.nonce + 1);
  }
  public Resolver = {
    resolve: async (didUrl) => this.getDocument(didUrl)
  }
  async getDocument(did, getBbsPlusSigKeys = true) {
    const { ss58ID, qualifier } = InfraSS58.splitDID(did)
    const offDocuments = (did) => ({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      controller: [did],
      verificationMethod: [
        {
          id: `${did}#keys-1`,
          type: 'Sr25519VerificationKey2020',
          controller: did,
          publicKeyBase58: b58.encode(decodeAddress(ss58ID)),
          publicKeyHex: u8aToHex(decodeAddress(ss58ID)).slice(2)
        }
      ],
      authentication: [`${did}#keys-1`,],
      assertionMethod: [`${did}#keys-1`,],
      keyAgreement: [],
      capabilityInvocation: [`${did}#keys-1`,],
      ATTESTS_IRI: null,
      service: []
    })
    const hexId = InfraSS58.didToHex(did);
    let didDetails
    try {
      didDetails = await this.getOnchainDIDDetail(hexId);
    } catch {
      return offDocuments(did);
    }
    const attests = await this.api.query.attest.attestations(hexId);
    const ATTESTS_IRI = attests.iri.isSome ? u8aToString(hexToU8a(attests.iri.toString())) : null;
    const id = (did === hexId) ? `${qualifier}${encodeAddress(hexId)}` : did;
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
        const [d, spId] = key.args;
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
          const [d, i] = key.args;
          const d_ = u8aToHex(d);
          if (d_ !== hexId) {
            throw new Error(`DID ${d_} was found to be different than queried DID ${hexId}`);
          }
          const index = i.toNumber();
          const pk = dk.publicKey;
          let publicKeyRaw, typ;
          if (pk.isSr25519) {
            typ = CRYPTO_INFO.SR25519.KEY_TYPE;
            publicKeyRaw = pk.asSr25519.value;
          } else if (pk.isEd25519) {
            typ = CRYPTO_INFO.ED25519.KEY_TYPE;
            publicKeyRaw = pk.asEd25519.value;
          } else {
            throw new Error(`Cannot parse public key ${pk}`);
          }
          keys.push([index, typ, publicKeyRaw]);
          const vr = new VerificationRelationship(dk.verRels.toNumber());
          if (vr.isAuthentication()) authn.push(index);
          if (vr.isAssertion()) assertion.push(index);
          if (vr.isCapabilityInvocation()) capInv.push(index);
          if (vr.isKeyAgreement()) keyAgr.push(index);
        }
      });
    }

    if (getBbsPlusSigKeys) {
      if (didDetails.lastKeyId > keys.length) {
        const possibleBbsPlusKeyIds = new Set();
        for (let i = 1; i <= didDetails.lastKeyId; i++) {
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
          const pr = (pk.paramsRef.isSome) ? pk.paramsRef.unwrap() : null
          return {
            bytes: u8aToHex(pk.bytes),
            curveType: pk.curveType.isBls12381 ? 'Bls12381' : null,
            paramsRef: pr ? [u8aToHex(pr[0]), pr[1].toNumber()] : null,
          };
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
      // publicKeyHex: u8aToHex(publicKeyRaw).slice(2),
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
      controller: controllers.map((c) => `${qualifier}${encodeAddress(c)}`),
      verificationMethod,
      authentication,
      assertionMethod,
      keyAgreement,
      capabilityInvocation,
      ATTESTS_IRI,
      service,
    };
  }


}

export default class InfraSS58DID extends InfraSS58 {

  private networkId;
  private verRels: VerificationRelationship;
  private seed: HexString;
  private address: string;
  private cryptoInfo: CRYPTO_INFO;
  private keyPairs: KeyringPair[];
  private publicKey: PublicKey;
  private didKey: DidKey;
  private did: string;
  private keyringModule: Keyring;
  private controllerDID: string;
  private controllerKeyPair: KeyringPair;
  get isConnected(): boolean {
    return this.api && this.api.isConnected || false;
  }

  private constructor() { super() }

  static async createNewSS58DIDSet(
    networkId: string,
    cryptoInfo: CRYPTO_INFO = CRYPTO_INFO.SR25519,
    verRels = new VerificationRelationship(),
  ): Promise<DIDSet> {

    const mnemonic = mnemonicGenerate()
    const seed = u8aToHex(mnemonicToMiniSecret(mnemonic));
    const keyPair = await InfraSS58DID.getKeyPairFromSeed(seed, cryptoInfo);
    const did = InfraSS58DID.ss58addrToDID(networkId, keyPair.address);
    const publicKey = PublicKey.fromKeyringPair(keyPair);
    const didKey: DidKey = new DidKey(publicKey, verRels);

    return { did, didKey, keyPair, publicKey, verRels, cryptoInfo, seed, mnemonic };
  }
  static async createAsync(conf: IConfig): Promise<InfraSS58DID> {
    return await new InfraSS58DID().init(conf)
  }

  private async init(conf: IConfig): Promise<InfraSS58DID> {
    if (this.api) {
      if (this.api.isConnected) {
        throw new Error('API is already connected');
      } else {
        await this.disconnect();
      }
    }
    this.networkId = conf.networkId
    this.cryptoInfo = conf.cryptoInfo ?? CRYPTO_INFO.SR25519;
    this.verRels = conf.verRels || new VerificationRelationship()

    await cryptoWaitReady();
    this.keyringModule = new Keyring({ type: this.cryptoInfo.CRYPTO_TYPE || CRYPTO_INFO.SR25519.CRYPTO_TYPE });

    this.address = conf.address || this.address;
    if (this.address && this.address.indexOf('wss://') === -1 && this.address.indexOf('https://') === -1) {
      console.warn(`WARNING: Using non-secure endpoint: ${this.address}`);
    }
    const isWebsocket = this.address && this.address.indexOf('http') === -1;
    const provider = isWebsocket ? new WsProvider(this.address) : new HttpProvider(this.address);
    const apiOptions = {
      provider,
      rpc: {},
      typesBundle: typesBundle,
    };
    this.api = await ApiPromise.create(apiOptions);

    if (conf.mnemonic) {
      this.seed = u8aToHex(mnemonicToMiniSecret(conf.mnemonic));
    } else if (conf.seed) {
      this.seed = conf.seed;
    } else {
      throw new Error('must provided seed or mnemonic')
    }
    this.keyPairs = [this.keyringModule.addFromUri(this.seed, undefined, this.cryptoInfo.CRYPTO_TYPE)];
    this.did = InfraSS58DID.ss58addrToDID(this.networkId, this.keyPairs[0].address);
    if (conf.did && this.did !== conf.did) {
      throw new Error('provided DID and seed not matched. check DID and seed(mnemonic)');
    }
    this.publicKey = PublicKey.fromKeyringPair(this.keyPairs[0]);
    this.didKey = new DidKey(this.publicKey, this.verRels);

    if (conf.txfeePayerAccountSeed) {
      this.accountKeyPair = this.keyringModule.addFromSeed(hexToU8a(conf.txfeePayerAccountSeed));
    } else if (conf.txfeePayerAccountKeyPair) {
      this.accountKeyPair = conf.txfeePayerAccountKeyPair
    } else {
      this.accountKeyPair = this.keyPairs[0]
    }
    if (conf.controllerDID && (conf.controllerKeyPair || conf.controllerSeed)) {
      this.controllerDID = conf.controllerDID;
      if (conf.controllerSeed) {
        this.controllerKeyPair = this.keyringModule.addFromSeed(hexToU8a(conf.controllerSeed))
      } else {
        this.controllerKeyPair = conf.controllerKeyPair;
      }
    } else {
      this.controllerDID = conf.did;
      this.controllerKeyPair = this.keyPairs[0]
    }

    await initializeWasm();
    return this
  }

  async getDocument(getBbsPlusSigKeys = true) {
    return super.getDocument(this.did, getBbsPlusSigKeys)
  }

  async registerOnChain() {
    try {
      const hexId = InfraSS58DID.didToHex(this.did);
      const didKeys = [this.didKey].map((d) => d.toJSON());
      const controllers = new BTreeSet(undefined, undefined, undefined)
      controllers.add(InfraSS58DID.didToHex(this.controllerDID) as unknown as Codec)
      const tx = await this.api.tx.didModule.newOnchain(hexId, didKeys, controllers);
      return this.signAndSend(tx, false, {});
    } catch (e) { throw e }
  }
  async unregisterOnChain() {
    try {
      const hexDID = InfraSS58DID.didToHex(this.did)
      const nonce = await this.getNextNonce(hexDID);
      const DidRemoval = { did: hexDID, nonce };
      const stateMessage = this.api.createType('StateChange', { DidRemoval }).toU8a();
      const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
      const tx = await this.api.tx.didModule.removeOnchainDid(DidRemoval, controllerDIDSig);
      return this.signAndSend(tx, false, {});
    } catch (e) { throw e }
  }

  async addKeys(...didKeys: DidKey[]) {
    const hexDID = InfraSS58DID.didToHex(this.did)
    const nonce = await this.getNextNonce(hexDID);
    const keys = didKeys.map((d) => d.toJSON());
    const AddKeys = { did: hexDID, keys, nonce };
    const stateMessage = this.api.createType('StateChange', { AddKeys }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = await this.api.tx.didModule.addKeys(AddKeys, controllerDIDSig);
    return await this.signAndSend(tx, false, {})
  }

  async removeKeys(...keyIds: number[]) {
    const hexDID = InfraSS58DID.didToHex(this.did)
    const nonce = await this.getNextNonce(hexDID);
    const keys = new BTreeSet(undefined, undefined, undefined);
    keyIds.forEach((keyId: unknown) => {
      keys.add(keyId as Codec);
    });
    const RemoveKeys = { did: hexDID, keys, nonce };
    const stateMessage = this.api.createType('StateChange', { RemoveKeys }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = await this.api.tx.didModule.removeKeys(RemoveKeys, controllerDIDSig);
    return await this.signAndSend(tx, false, {})
  }

  async addControllers(...controllerDIDs: string[]) {
    const hexDID = InfraSS58DID.didToHex(this.did)
    const nonce = await this.getNextNonce(hexDID);
    const controllers = new BTreeSet(undefined, undefined, undefined);
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = InfraSS58DID.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });
    const AddControllers = { did: hexDID, controllers, nonce };
    const stateMessage = this.api.createType('StateChange', { AddControllers }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = this.api.tx.didModule.addControllers(AddControllers, controllerDIDSig);
    return await this.signAndSend(tx, false, {});
  }

  async removeControllers(...controllerDIDs: string[]) {
    const hexDID = InfraSS58DID.didToHex(this.did)
    const nonce = await this.getNextNonce(hexDID);
    const controllers = new BTreeSet(undefined, undefined, undefined);
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = InfraSS58DID.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });
    const RemoveControllers = { did: hexDID, controllers, nonce };
    const stateMessage = this.api.createType('StateChange', { RemoveControllers }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = this.api.tx.didModule.removeControllers(RemoveControllers, controllerDIDSig);
    return await this.signAndSend(tx, false, {});
  }

  async addServiceEndpoint(
    originsTexts: string[],
    endpointType?: ServiceEndpointType,
    endpointIdText?: string,
  ) {
    const encoder = new TextEncoder();
    const hexDID = InfraSS58DID.didToHex(this.did)
    const nonce = await this.getNextNonce(hexDID);
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    if (!endpointType) {
      endpointType = new ServiceEndpointType()
      endpointType.setLinkedDomains()
    }
    const origins = originsTexts.map((u) => u8aToHex(encoder.encode(u)));
    const endpoint = { types: endpointType.value, origins };
    const hexID = u8aToHex(encoder.encode(endpointIdText));
    const AddServiceEndpoint = { did: hexDID, id: hexID, endpoint, nonce };
    const stateMessage = this.api.createType('StateChange', { AddServiceEndpoint }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = this.api.tx.didModule.addServiceEndpoint(AddServiceEndpoint, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async removeServiceEndpoint(endpointIdText?: string) {
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    const spId = u8aToHex(encoder.encode(endpointIdText));
    const hexDID = InfraSS58DID.didToHex(this.did)
    const nonce = await this.getNextNonce(hexDID);
    const RemoveServiceEndpoint = { did: hexDID, id: spId, nonce };
    const stateMessage = this.api.createType('StateChange', { RemoveServiceEndpoint }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = this.api.tx.didModule.removeServiceEndpoint(RemoveServiceEndpoint, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async getServiceEndpoint(endpointIdText?: string) {
    const hexDID = InfraSS58DID.didToHex(this.did);
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

  async isController(controllerDID: string): Promise<boolean> {
    const controlledHexId = InfraSS58DID.didToHex(this.did);
    const controllerHexId = InfraSS58DID.didToHex(controllerDID);
    const resp = await this.api.query.didModule.didControllers(
      controlledHexId,
      controllerHexId,
    );
    return resp.isSome;
  }
  async setClaim(priority: number, iri: string) {
    const encoder = new TextEncoder();
    const hexDID = InfraSS58DID.didToHex(this.did);
    const nonce = await this.getNextNonce(hexDID);
    const attest = { priority, iri: u8aToHex(encoder.encode(iri)) };
    const SetAttestationClaim = { attest, nonce };
    const stateMessage = this.api.createType('StateChange', { SetAttestationClaim }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = this.api.tx.attest.setClaim(SetAttestationClaim, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }


  //****************************************************************************
  // * 
  // * BBS+ module
  // * 
  //****************************************************************************

  static BBSPlus_createNewSigSet(messageCounter = 10, label?: string): BBSPlus_SigSet {
    const sigParam = InfraSS58DID.BBSPlus_createSigParamsWithLabel(messageCounter, label)
    const keyPair = InfraSS58DID.BBSPlus_createKeyPair(sigParam)
    const publicKey = InfraSS58DID.BBSPlus_createSigPublicKey(keyPair)
    return { sigParam, keyPair, publicKey, messageCounter, label }
  }
  async BBSPlus_createNewSigSet(paramCounter = 1): Promise<BBSPlus_SigSet> {
    const sigParam = await this.BBSPlus_createSigParamsByDID(paramCounter)
    const keyPair = InfraSS58DID.BBSPlus_createKeyPair(sigParam)
    const publicKey = InfraSS58DID.BBSPlus_createSigPublicKey(keyPair)
    return { sigParam, keyPair, publicKey, paramCounter }
  }
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
    return await new SignatureParamsG1(params1Val, hexToU8a(queriedParams.label));
  }
  static BBSPlus_createKeyPair(sigParams: SignatureParamsG1): KeypairG2 {
    return KeypairG2.generate(sigParams);

  }
  static BBSPlus_createSigPublicKey(keypair: KeypairG2, params = undefined): BBSPlus_PublicKey {
    // params= [did, paramCounter]
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
    return {
      bytes: u8aToHex(keypair.publicKey.bytes),
      paramsRef,
      curveType: 'Bls12381'
    };
  }

  private async BBSPlus_getParamsByHexDid(hexDid: HexString, paramCounter: number): Promise<BBSPlus_Params> {
    const resp = await this.api.query.bbsPlus.bbsPlusParams(hexDid, paramCounter);
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

  private async BBSPlus_getPublicKeyByHexDid(hexDid: HexString, keyId: number, withParams = false): Promise<BBSPlus_PublicKey> {
    const resp = await this.api.query.bbsPlus.bbsPlusKeys(hexDid, keyId);
    if (resp.isSome) {
      const pk = resp.unwrap();
      let paramsRef = null
      if (pk.paramsRef.isSome) {
        const pr = pk.paramsRef.unwrap();
        paramsRef = [u8aToHex(pr[0]), pr[1].toNumber()]
      }
      const pkObj: BBSPlus_PublicKey = {
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
    const hexDID = InfraSS58DID.didToHex(this.did);
    const nonce = await this.getNextNonce(hexDID);
    const AddBBSPlusPublicKey = { key: publicKey, did: hexDID, nonce };
    const stateMessage = this.api.createType('StateChange', { AddBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = await this.api.tx.bbsPlus.addPublicKey(AddBBSPlusPublicKey, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async BBSPlus_removePublicKey(removeKeyId: number) {
    const hexDID = InfraSS58DID.didToHex(this.did);
    const nonce = await this.getNextNonce(hexDID);
    const RemoveBBSPlusPublicKey = { keyRef: [hexDID, removeKeyId], did: hexDID, nonce };
    const stateMessage = this.api.createType('StateChange', { RemoveBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = await this.api.tx.bbsPlus.removePublicKey(RemoveBBSPlusPublicKey, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async BBSPlus_getPublicKey(keyId: number, withParams = false): Promise<BBSPlus_PublicKey> {
    const hexId = InfraSS58DID.didToHex(this.did);
    return this.BBSPlus_getPublicKeyByHexDid(hexId, keyId, withParams);
  }

  async BBSPlus_addParams(sigParam: SignatureParamsG1, label?: string) {
    const hexDID = InfraSS58DID.didToHex(this.did);
    const nonce = await this.getNextNonce(hexDID);
    const params = {
      bytes: u8aToHex(sigParam.toBytes()),
      curveType: 'Bls12381',
      label
    }
    const AddBBSPlusParams = { params, nonce };
    const stateMessage = this.api.createType('StateChange', { AddBBSPlusParams }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = await this.api.tx.bbsPlus.addParams(AddBBSPlusParams, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async BBSPlus_removeParams(paramCounter: number) {
    const hexDID = InfraSS58DID.didToHex(this.did);
    const nonce = await this.getNextNonce(hexDID);
    const RemoveBBSPlusParams = { paramsRef: [hexDID, paramCounter], nonce };
    const stateMessage = this.api.createType('StateChange', { RemoveBBSPlusParams }).toU8a();
    const controllerDIDSig = this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);
    const tx = await this.api.tx.bbsPlus.removeParams(RemoveBBSPlusParams, controllerDIDSig);
    return this.signAndSend(tx, false, {});
  }

  async BBSPlus_getParams(paramCounter: number): Promise<BBSPlus_Params> {
    const hexId = InfraSS58DID.didToHex(this.did);
    return await this.BBSPlus_getParamsByHexDid(hexId, paramCounter);
  }

  async BBSPlus_getLastParamsWritten(): Promise<BBSPlus_Params> {
    const hexId = InfraSS58DID.didToHex(this.did);
    const lastCounter: number = await this.api.query.bbsPlus.paramsCounter(hexId);
    if (lastCounter < 1) return null
    return await this.BBSPlus_getParamsByHexDid(hexId, lastCounter)
  }

  async BBSPlus_getAllParams(): Promise<BBSPlus_Params[]> {
    const hexId = InfraSS58DID.didToHex(this.did);
    const params = [];
    const lastCounter: number = await this.api.query.bbsPlus.paramsCounter(hexId);
    if (lastCounter > 0) {
      for (let counter = 1; counter <= lastCounter; counter++) {
        const param = await this.BBSPlus_getParamsByHexDid(hexId, counter);
        if (param !== null) {
          params.push(param);
        }
      }
    }
    return params;
  }



  //****************************************************************************
  // * 
  // * Schema RPC module
  // * 
  //****************************************************************************

  async writeSchemaOnChain(blobSchema) {
    return await this.api.blob.new(blobSchema, this.did, this.keyPairs[0], 1, { didModule: this.api.did }, false, {})
  }

}
