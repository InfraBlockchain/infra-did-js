import { ApiPromise, Keyring, WsProvider } from '@polkadot/api';
import { HttpProvider } from '@polkadot/rpc-provider';
import { u8aToString, hexToU8a, u8aToHex, stringToHex, bufferToU8a } from '@polkadot/util';
import elliptic from 'elliptic';
import b58 from 'bs58';
import { sha256 } from 'js-sha256';
import {
  encodeAddress, decodeAddress,
  mnemonicGenerate, mnemonicToMiniSecret,
  cryptoWaitReady, blake2AsHex, randomAsHex
} from '@polkadot/util-crypto';
import { initializeWasm, KeypairG2, SignatureParamsG1 } from '@docknetwork/crypto-wasm-ts';

import { DID_QUALIFIER } from './infra-ss58-verifiable/const';
import {
  typesBundle, BTreeSet, Codec, ServiceEndpointType, ExtrinsicError,
  CRYPTO_INFO, SIG_TYPE, HexString, IConfig_SS58, KeyPair, KeyringPair,
  BBSPlus_Params, BBSPlus_PublicKey, BBSPlus_SigSet,
  DIDSet, DidKey_SS58, PublicKey_SS58,
  VerificationRelationship
} from './ss58.interface';
import { VerifiableCredential, VerifiablePresentation, Schema } from './infra-ss58-verifiable';

export {
  CRYPTO_INFO, SIG_TYPE, HexString, IConfig_SS58, KeyPair, KeyringPair,
  BBSPlus_Params, BBSPlus_PublicKey, BBSPlus_SigSet,
  DIDSet, DidKey_SS58, PublicKey_SS58, Schema,
  VerificationRelationship, VerifiableCredential, VerifiablePresentation
}

const secp256k1 = new elliptic.ec('secp256k1');

export default class InfraSS58 {
  api!: any;

  get isConnected(): boolean {
    return this.api && this.api.isConnected || false;
  }
  private address!: string;
  networkId!: string;
  accountKeyPair;
  cryptoInfo: CRYPTO_INFO;
  controllerDID: string;
  controllerKeyPair: KeyPair;
  keyringModule: Keyring;
  didModule: InfraSS58_DID;
  bbsModule: InfraSS58_BBS;
  blobModule: InfraSS58_BLOB;
  revocationModule: InfraSS58_Revocation;
  infraDidResolver
  didResolver
  private constructor() {}

  static async createAsync(conf: IConfig_SS58): Promise<InfraSS58> {
    return await new InfraSS58().initApi(conf)
  }
  static async createNewSS58DIDSet(
    networkId: string,
    cryptoInfo: CRYPTO_INFO = CRYPTO_INFO.SR25519,
    seed?: HexString,
    verRels = new VerificationRelationship(),
  ): Promise<DIDSet> {
    seed ??= u8aToHex(mnemonicToMiniSecret(mnemonicGenerate()));
    const keyPair = await InfraSS58.getKeyPairFromSeed(seed, cryptoInfo);
    const publicKey = PublicKey_SS58.fromKeyringPair(keyPair);
    const did = InfraSS58.keyPairToDID(networkId, keyPair);
    const didKey = new DidKey_SS58(publicKey, verRels);
    return { did, didKey, keyPair, publicKey, verRels, cryptoInfo, seed };
  }

  static BBSPlus_createNewSigSet(messageCounter = 10, label?: string): BBSPlus_SigSet {
    const sigParam = InfraSS58.BBSPlus_createSigParamsWithLabel(messageCounter, label)
    const keyPair = InfraSS58.BBSPlus_createKeyPair(sigParam)
    const publicKey = InfraSS58.BBSPlus_createSigPublicKey(keyPair)
    return { sigParam, keyPair, publicKey, messageCounter, label }
  }
  static BBSPlus_changeSigParamMessageCounter(sigParam: SignatureParamsG1, messageCounter: number): SignatureParamsG1 {
    return sigParam.adapt(messageCounter)
  }
  static BBSPlus_createSigParamsWithLabel(messageCounter: number, label?: string): SignatureParamsG1 {
    return label ?
      SignatureParamsG1.generate(messageCounter, hexToU8a(label)) :
      SignatureParamsG1.generate(messageCounter)
  }
  static BBSPlus_createKeyPair(sigParams: SignatureParamsG1): KeypairG2 {
    return KeypairG2.generate(sigParams);

  }
  static BBSPlus_createSigPublicKey(keypair: KeypairG2, params: any = undefined): BBSPlus_PublicKey {
    // params= [did, paramCounter]
    let paramsRef: any = undefined;
    if (params) {
      if (!(typeof params === 'object' && params instanceof Array && params.length === 2)) {
        throw new Error('Reference should be an array of 2 items');
      }
      if (typeof params[1] !== 'number') {
        throw new Error(`Second item of reference should be a number but was ${params[1]}`);
      }
      const hexDID = InfraSS58.didToHex(params[0])
      paramsRef = [hexDID, params[1]]
    }
    return {
      bytes: u8aToHex(keypair.publicKey.bytes),
      paramsRef,
      curveType: 'Bls12381'
    };
  }
  public getKeyDoc() {
    return {
      id: `${this.didModule.did}#keys-1`,
      controller: this.didModule.did,
      type: this.cryptoInfo.KEY_TYPE,
      keypair: this.didModule.keyPairs[0],
    };
  }
  public getChallenge() {
    return this.didModule.challenge
  }
  protected async initApi(conf: IConfig_SS58): Promise<this> {
    if (this.api) {
      if (this.api.isConnected) {
        throw new Error('API is already connected');
      } else {
        await this.disconnect()
      }
    }
    this.cryptoInfo = conf.cryptoInfo ?? CRYPTO_INFO.SR25519;
    await cryptoWaitReady();
    this.keyringModule = new Keyring({ type: this.cryptoInfo.CRYPTO_TYPE || CRYPTO_INFO.SR25519.CRYPTO_TYPE });
    this.networkId = conf.networkId;
    this.address = conf.address;
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
    // @ts-ignore
    this.api = await ApiPromise.create(apiOptions);

    if (conf.txfeePayerAccountSeed) {
      this.accountKeyPair = this.keyringModule.addFromSeed(hexToU8a(conf.txfeePayerAccountSeed));
    } else if (conf.txfeePayerAccountKeyPair) {
      this.accountKeyPair = conf.txfeePayerAccountKeyPair
    }

    if (conf.controllerDID && (conf.controllerKeyPair || conf.controllerSeed)) {
      this.controllerDID = conf.controllerDID
      if (conf.controllerSeed) {
        this.controllerKeyPair = this.keyringModule.addFromSeed(hexToU8a(conf.controllerSeed))
      } else if (conf.controllerKeyPair) {
        this.controllerKeyPair = conf.controllerKeyPair;
      }
    };

    this.didModule = await InfraSS58_DID.createAsync(conf, this);
    this.bbsModule = new InfraSS58_BBS(this);
    this.blobModule = new InfraSS58_BLOB(this);
    this.revocationModule = new InfraSS58_Revocation(this);

    await initializeWasm();
    return this;
  }

  static splitDID(did: string) {
    const splitDID = did.split('#')[0].split(':') || []
    return {
      id: splitDID.pop() || '',
      qualifier: splitDID.join(':'),
    }
  }
  static didToHex(did: string): HexString {
    const { id: ss58ID } = InfraSS58.splitDID(did);
    return u8aToHex(decodeAddress(ss58ID));
  }

  static async getKeyPairFromSeed(seed: HexString, cryptoInfo: CRYPTO_INFO): Promise<KeyPair> {
    if (cryptoInfo.CRYPTO_TYPE === 'ecdsa') {
      return secp256k1.genKeyPair({ entropy: seed });
    } else {
      return InfraSS58.getKeyringPairFromUri(seed, cryptoInfo);
    }
  }
  static async getKeyringPairFromUri(uri, cryptoInfo?: CRYPTO_INFO): Promise<KeyringPair> {
    const cryptoType = cryptoInfo?.CRYPTO_TYPE || CRYPTO_INFO.SR25519.CRYPTO_TYPE
    const keyringModule = new Keyring({ type: cryptoType });
    await cryptoWaitReady();
    return keyringModule.addFromUri(uri, undefined, cryptoType);

  }
  static ss58addrToDID(networkId: string, addr: string) { return `${DID_QUALIFIER}${networkId}:${addr}` }
  static keyPairToDID(networkId: string, keyPair: KeyPair) {
    if ((keyPair as KeyringPair).type)
      return InfraSS58.ss58addrToDID(networkId, (keyPair as KeyringPair).address)
    return `${DID_QUALIFIER}${networkId}:${encodeAddress(`0x${(keyPair as elliptic.ec.KeyPair).getPublic(true, 'hex').slice(0, 64)}`)}`;

  }
  static validateInfraSS58DID(infraSS58DID: string): { result: boolean, errMsg?: string } {
    const didSplit = infraSS58DID.split(':')
    if (didSplit.length !== 4) {
      return { result: false, errMsg: `invalid infraSS58DID, needs network identifier part and id part (${infraSS58DID})` }
    }
    const regex = new RegExp(/^[5KL][1-9A-HJ-NP-Za-km-z]{47}$/);
    const matches = regex.exec(didSplit[3]);
    if (!matches) {
      return { result: false, errMsg: 'The identifier must be 32 bytes and valid SS58 string' }
    }
    return { result: true }
  }
  private signPrehashed(stateMessage, keyPair) {
    const messageHash = sha256.digest(stateMessage);
    const sig = keyPair.sign(messageHash, { canonical: true });
    // The signature is recoverable in 65-byte { R | S | index } format
    const r = sig.r.toString('hex', 32);
    const s = sig.s.toString('hex', 32);
    const i = sig.recoveryParam.toString(16).padStart(2, '0');
    // Make it proper hex
    return `0x${r}${s}${i}`;
  }
  protected getSig(sigType: SIG_TYPE, keyPair, stateMessage) {
    if (sigType === CRYPTO_INFO.Secp256k1.SIG_TYPE) {
      return { [sigType]: this.signPrehashed(stateMessage, keyPair) }
    } else
      return { [sigType]: u8aToHex(keyPair.sign(stateMessage)) }
  }

  getDIDSig(did: string, sigType: SIG_TYPE, keyPair: KeyPair, stateMessage, keyId = 1) {
    return {
      did: InfraSS58.didToHex(did),
      keyId,
      sig: this.getSig(sigType, keyPair, stateMessage)
    }
  }
  public getControllerDIDSig(stateMessage: any) {
    return this.getDIDSig(this.controllerDID, this.cryptoInfo.SIG_TYPE, this.controllerKeyPair, stateMessage);

  }
  public getSerializedBlobValue(blobValue) {
    if (blobValue instanceof Uint8Array) {
      return [...blobValue];
    } else if (typeof blobValue === 'object') {
      return stringToHex(JSON.stringify(blobValue));
    } else if (typeof blobValue === 'string') {
      return stringToHex(blobValue);
    }
    return blobValue;
  }


  public async signAndSend(extrinsic, waitForFinalization = true, params = {}) {
    // @ts-ignore
    params.nonce = await this.api.rpc.system.accountNextIndex(this.accountKeyPair.address);
    const signedExtrinsic = await extrinsic.signAsync(this.accountKeyPair, params)
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
  public async disconnect() {
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
  public async getNextNonce(hexDID: HexString): Promise<number> {
    return await this.getOnchainDIDDetail(hexDID).then(detail => detail.nonce + 1);
  }
  public Resolver = {
    resolve: async (didUrl) => this.getDocument(didUrl)
  }
  public async getDocument(did, getBbsPlusSigKeys = true) {
    did = did.split('#')[0];
    const { id: ss58ID, qualifier } = InfraSS58.splitDID(did);
    const publicKey = decodeAddress(ss58ID);
    const offDocuments = (did) => ({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      controller: [did],
      verificationMethod: [
        {
          id: `${did}#keys-1`,
          type: 'unknown',// TODO offchain DID에서는 SR25519, ED25519, Secp256k1 구분 불가...
          controller: did,
          publicKeyBase58: b58.encode(publicKey),
          // publicKeyHex: u8aToHex(publicKey).slice(2)
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
    const controllers: any[] = [];
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

    const serviceEndpoints: any[] = [];
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

    const keys: any[] = [];
    const assertion: any[] = [];
    const authn: any[] = [];
    const capInv: any[] = [];
    const keyAgr: any[] = [];
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
          } else if (pk.isSecp256k1) {
            typ = CRYPTO_INFO.Secp256k1.KEY_TYPE;
            publicKeyRaw = pk.asSecp256k1.value;
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

        const queryKeys: any[] = [];
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
    let service: any[] = [];
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

class InfraSS58_DID {

  private verRels: VerificationRelationship;
  did: string;
  keyPairs: KeyPair[];
  private publicKey: PublicKey_SS58;

  private didKey: DidKey_SS58;

  private that: InfraSS58;
  challenge: any;


  private constructor(that: InfraSS58) { this.that = that }
  static async createAsync(conf: IConfig_SS58, apiModule: InfraSS58): Promise<InfraSS58_DID> {
    return await new InfraSS58_DID(apiModule).initModule(conf)
  }
  private async initModule(conf: IConfig_SS58): Promise<InfraSS58_DID> {
    this.verRels = conf.verRels || new VerificationRelationship()
    if (conf.seed) {
      const { did, didKey, keyPair, publicKey } = await InfraSS58.createNewSS58DIDSet(conf.networkId, conf.cryptoInfo, conf.seed, conf.verRels)
      this.did = did;
      this.keyPairs = [keyPair];
      this.publicKey = publicKey;
      this.didKey = didKey;
    } else if (conf.keyPair) {
      this.keyPairs = [conf.keyPair];
      this.did = conf.did;
      this.publicKey = PublicKey_SS58.fromKeyringPair(this.keyPairs[0]);
      this.didKey = new DidKey_SS58(this.publicKey, this.verRels);
    } else {
      throw new Error("seed or keyPair required");
    }
    if (this.did !== conf.did) {
      throw new Error("DID does not match the given seed or keyPair.");
    }
    this.challenge = randomAsHex(32);

    this.that.controllerDID ??= this.did;
    this.that.controllerKeyPair ??= this.keyPairs[0]
    this.that.accountKeyPair ??= this.keyPairs[0]
    return this
  }

  async getDocument(getBbsPlusSigKeys = true) {
    return this.that.getDocument(this.did, getBbsPlusSigKeys)
  }


  async registerDIDOnChain(did: string, didKey, controllerDID?: string) {
    const hexId = InfraSS58.didToHex(did);
    const didKeys = [didKey].map((d) => d.toJSON ? d.toJSON() : d);
    // @ts-ignore
    const controllers = new BTreeSet();
    controllers.add(InfraSS58.didToHex(controllerDID) as unknown as Codec)

    const tx = await this.that.api.tx.didModule.newOnchain(hexId, didKeys, controllers);
    return this.that.signAndSend(tx, false, {});
  }
  async registerOnChain() {
    return await this.registerDIDOnChain(this.did, this.didKey, this.that.controllerDID);
  }

  async unregisterDIDOnChain(did, controllerDID, controllerSigType, contollerKeyPair) {
    const hexDID = InfraSS58.didToHex(did)
    const nonce = await this.that.getNextNonce(hexDID);
    const DidRemoval = { did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { DidRemoval }).toU8a();
    const controllerDIDSig = this.that.getDIDSig(controllerDID, controllerSigType, contollerKeyPair, stateMessage)
    const tx = await this.that.api.tx.didModule.removeOnchainDid(DidRemoval, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }
  async unregisterOnChain() {
    return this.unregisterDIDOnChain(this.did, this.that.controllerDID, this.that.cryptoInfo.SIG_TYPE, this.keyPairs[0]);
  }

  async addKeys(...didKeys: DidKey_SS58[]) {
    const hexDID = InfraSS58.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    const keys = didKeys.map((d) => d.toJSON());
    const AddKeys = { did: hexDID, keys, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddKeys }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);

    const tx = await this.that.api.tx.didModule.addKeys(AddKeys, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {})
  }

  async removeKeys(...keyIds: number[]) {
    const hexDID = InfraSS58.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    // @ts-ignore
    const keys = new BTreeSet();
    keyIds.forEach((keyId: unknown) => {
      keys.add(keyId as Codec);
    });
    const RemoveKeys = { did: hexDID, keys, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveKeys }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.didModule.removeKeys(RemoveKeys, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {})
  }

  async addControllers(...controllerDIDs: string[]) {
    const hexDID = InfraSS58.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    // @ts-ignore
    const controllers = new BTreeSet();
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = InfraSS58.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });
    const AddControllers = { did: hexDID, controllers, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddControllers }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.addControllers(AddControllers, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {});
  }

  async removeControllers(...controllerDIDs: string[]) {
    const hexDID = InfraSS58.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    // @ts-ignore
    const controllers = new BTreeSet();
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = InfraSS58.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });
    const RemoveControllers = { did: hexDID, controllers, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveControllers }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.removeControllers(RemoveControllers, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {});
  }

  async addServiceEndpoint(
    originsTexts: string[],
    endpointType?: ServiceEndpointType,
    endpointIdText?: string,
  ) {
    const encoder = new TextEncoder();
    const hexDID = InfraSS58.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    if (!endpointType) {
      endpointType = new ServiceEndpointType()
      endpointType.setLinkedDomains()
    }
    const origins = originsTexts.map((u) => u8aToHex(encoder.encode(u)));
    const endpoint = { types: endpointType.value, origins };
    const hexID = u8aToHex(encoder.encode(endpointIdText));
    const AddServiceEndpoint = { did: hexDID, id: hexID, endpoint, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddServiceEndpoint }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.addServiceEndpoint(AddServiceEndpoint, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removeServiceEndpoint(endpointIdText?: string) {
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    const spId = u8aToHex(encoder.encode(endpointIdText));
    const hexDID = InfraSS58.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    const RemoveServiceEndpoint = { did: hexDID, id: spId, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveServiceEndpoint }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.removeServiceEndpoint(RemoveServiceEndpoint, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getServiceEndpoint(endpointIdText?: string) {
    const hexDID = InfraSS58.didToHex(this.did);
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    const spId = u8aToHex(encoder.encode(endpointIdText));
    let resp = await this.that.api.query.didModule.didServiceEndpoints(hexDID, spId,);
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
    const controlledHexId = InfraSS58.didToHex(this.did);
    const controllerHexId = InfraSS58.didToHex(controllerDID);
    const resp = await this.that.api.query.didModule.didControllers(
      controlledHexId,
      controllerHexId,
    );
    return resp.isSome;
  }
  async setClaim(priority: number, iri: string) {
    const encoder = new TextEncoder();
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const attest = { priority, iri: u8aToHex(encoder.encode(iri)) };
    const SetAttestationClaim = { attest, nonce };
    const stateMessage = this.that.api.createType('StateChange', { SetAttestationClaim }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.attest.setClaim(SetAttestationClaim, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }
}

class InfraSS58_BLOB {
  that: InfraSS58;
  did: string;
  constructor(that: InfraSS58) {
    this.that = that;
    this.did = that.didModule.did
  }
  async writeSchemaOnChainByBlob(blobSchema) {
    const hexId = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexId);

    const AddBlob = {
      blob: { ...blobSchema, blob: this.that.getSerializedBlobValue(blobSchema.blob) },
      nonce
    };

    const stateMessage = this.that.api.createType('StateChange', { AddBlob }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.blobStore.new(AddBlob, controllerDIDSig);
    return this.that.signAndSend(tx, false, {})
  }

  async getSchema(blobId: string) {
    const hexId = Schema.getHexIdFromBlobId(blobId);

    const resp = await this.that.api.query.blobStore.blobs(hexId);
    if (resp.isNone) {
      throw new Error(`Blob ID (${blobId}) does not exist`);
    }
    const respTuple = resp.unwrap();
    if (respTuple.length === 2) {
      let chainValue: Uint8Array | object = bufferToU8a(respTuple[1]);
      const strValue = u8aToString(chainValue as Uint8Array);
      if (strValue.substring(0, 1) === '{') {
        chainValue = JSON.parse(strValue);
      }

      if (typeof chainValue === 'object' && !(chainValue instanceof Uint8Array)) {
        const ss58Id = encodeAddress(u8aToHex(respTuple[0]));
        const author = `${DID_QUALIFIER}${this.that.networkId}${ss58Id}`;
        return { schema: chainValue, id: blobId, author };
      }
      throw new Error('Incorrect schema format');
    }
  }
}

class InfraSS58_BBS {
  did: string;
  constructor(private that: InfraSS58) {
    this.did = that.didModule.did
  }

  async createNewSigSet(paramCounter = 1): Promise<BBSPlus_SigSet> {
    const sigParam = await this.createSigParamsByDID(paramCounter)
    const keyPair = InfraSS58.BBSPlus_createKeyPair(sigParam)
    const publicKey = InfraSS58.BBSPlus_createSigPublicKey(keyPair)
    return { sigParam, keyPair, publicKey, paramCounter }
  }
  async createSigParamsByDID(paramCounter: number)
    : Promise<SignatureParamsG1> {
    const queriedParams = await this.getParams(paramCounter);
    const params1Val = SignatureParamsG1.valueFromBytes(hexToU8a(queriedParams?.bytes));
    return await new SignatureParamsG1(params1Val, hexToU8a(queriedParams?.label));
  }
  private async getParamsByHexDid(hexDid: HexString, paramCounter: number): Promise<BBSPlus_Params | null> {
    const resp = await this.that.api.query.bbsPlus.bbsPlusParams(hexDid, paramCounter);
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

  private async getPublicKeyByHexDid(hexDid: HexString, keyId: number, withParams = false): Promise<BBSPlus_PublicKey | null> {
    const resp = await this.that.api.query.bbsPlus.bbsPlusKeys(hexDid, keyId);
    if (resp.isSome) {
      const pk = resp.unwrap();
      let paramsRef: any = null
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
        } else if (pkObj.paramsRef) {
          const params = await this.getParamsByHexDid(pkObj.paramsRef[0], pkObj.paramsRef[1]);
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

  async addPublicKey(publicKey: BBSPlus_PublicKey) {
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const AddBBSPlusPublicKey = { key: publicKey, did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.addPublicKey(AddBBSPlusPublicKey, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removePublicKey(removeKeyId: number) {
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const RemoveBBSPlusPublicKey = { keyRef: [hexDID, removeKeyId], did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.removePublicKey(RemoveBBSPlusPublicKey, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getPublicKey(keyId: number, withParams = false): Promise<BBSPlus_PublicKey | null> {
    const hexId = InfraSS58.didToHex(this.did);
    return this.getPublicKeyByHexDid(hexId, keyId, withParams);
  }

  async addParams(sigParam: SignatureParamsG1, label?: string) {
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const params = {
      bytes: u8aToHex(sigParam.toBytes()),
      curveType: 'Bls12381',
      label
    }
    const AddBBSPlusParams = { params, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddBBSPlusParams }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.addParams(AddBBSPlusParams, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removeParams(paramCounter: number) {
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const RemoveBBSPlusParams = { paramsRef: [hexDID, paramCounter], nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveBBSPlusParams }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.removeParams(RemoveBBSPlusParams, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getParams(paramCounter: number): Promise<BBSPlus_Params | null> {
    const hexId = InfraSS58.didToHex(this.did);
    return await this.getParamsByHexDid(hexId, paramCounter);
  }

  async getLastParamsWritten(): Promise<BBSPlus_Params | null> {
    const hexId = InfraSS58.didToHex(this.did);
    const lastCounter: number = await this.that.api.query.bbsPlus.paramsCounter(hexId);
    if (lastCounter < 1) return null
    return await this.getParamsByHexDid(hexId, lastCounter)
  }

  async getAllParams(): Promise<BBSPlus_Params[]> {
    const hexId = InfraSS58.didToHex(this.did);
    const params: any = [];
    const lastCounter: number = await this.that.api.query.bbsPlus.paramsCounter(hexId);
    if (lastCounter > 0) {
      for (let counter = 1; counter <= lastCounter; counter++) {
        const param = await this.getParamsByHexDid(hexId, counter);
        if (param !== null) {
          params.push(param);
        }
      }
    }
    return params;
  }

}


class InfraSS58_Revocation {
  private policyOwner: string[];

  constructor(private that: InfraSS58) {
    this.policyOwner = [];
  }
  public createNewRegistryId() {
    return randomAsHex(32);
  }
  public getRevokeId(vcId) {
    return blake2AsHex(vcId, 256);
  }
  public async newRegistry(id: HexString, addOnly = false) {
    if (!this.policyOwner || this.policyOwner.length < 1) { this.addPolicyOwner() }
    const addReg = { id, newRegistry: { policy: this.getPolicyOwner(), addOnly } };
    const tx = this.that.api.tx.revoke.newRegistry(addReg);
    return this.that.signAndSend(tx, false, {});
  }

  public async revokeCredentialWithOneOfPolicy(registryId, revId) {
    const { did, keyPairs } = this.that.didModule
    const { cryptoInfo } = this.that
    const hexDid = InfraSS58.didToHex(did);
    const nonce = await this.that.getNextNonce(hexDid);

    const Revoke = { data: { registryId, revokeIds: [revId], }, nonce, };
    const serializedRevoke = this.that.api.createType('StateChange', { Revoke }).toU8a();
    const didSig = this.that.getDIDSig(did, cryptoInfo.SIG_TYPE, keyPairs[0], serializedRevoke, 1);
    const revoke = { registryId, revokeIds: [revId] };
    const tx = this.that.api.tx.revoke.revoke(revoke, [[didSig, nonce]]);
    return this.that.signAndSend(tx, false, {});
  }

  public async unrevokeCredentialWithOneOfPolicy(registryId, revId) {
    const { did, keyPairs } = this.that.didModule
    const { cryptoInfo } = this.that
    const hexDid = InfraSS58.didToHex(did);
    const nonce = await this.that.getNextNonce(hexDid);

    const UnRevoke = { data: { registryId, revokeIds: [revId], }, nonce, };
    const serializedRevoke = this.that.api.createType('StateChange', { UnRevoke }).toU8a();
    const didSig = this.that.getDIDSig(did, cryptoInfo.SIG_TYPE, keyPairs[0], serializedRevoke, 1);
    const unrevoke = { registryId, revokeIds: [revId] };
    const tx = this.that.api.tx.revoke.unrevoke(unrevoke, [[didSig, nonce]]);
    return this.that.signAndSend(tx, false, {});
  }

  public async removeRegistryWithOneOfPolicy(registryId) {
    const { did, keyPairs } = this.that.didModule
    const { cryptoInfo } = this.that
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    const RemoveRegistry = {
      data: { registryId },
      nonce,
    };
    const serializedRemove = this.that.api.createType('StateChange', { RemoveRegistry }).toU8a();
    const didSig = this.that.getDIDSig(did, cryptoInfo.SIG_TYPE, keyPairs[0], serializedRemove, 1);
    const removal = { registryId };
    const tx = this.that.api.tx.revoke.removeRegistry(removal, [[didSig, nonce]]);
    return this.that.signAndSend(tx, false, {});
  }
  public async getRevocationRegistry(registryID) {
    const resp = await this.that.api.query.revoke.registries(registryID);
    if (resp.isNone) {
      throw new Error(`Could not find revocation registry: ${registryID}`);
    }
    return resp.unwrap();
  }
  public async getIsRevoked(registryId, revokeId) {
    const resp = await this.that.api.query.revoke.revocations(registryId, revokeId);
    return !resp.isNone;
  }
  public getPolicyOwner() {
    return {
      OneOf: this.policyOwner.sort(),
    }
  }
  public addPolicyOwner(ownerDID?: string) {
    ownerDID ??= this.that.didModule.did
    this.policyOwner.push(InfraSS58.didToHex(ownerDID))
  }
}
