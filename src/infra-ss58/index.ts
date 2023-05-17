import { ApiPromise, Keyring, WsProvider } from '@polkadot/api';
import { HttpProvider } from '@polkadot/rpc-provider';
import { u8aToString, hexToU8a, u8aToHex, stringToHex, bufferToU8a, stringToU8a } from '@polkadot/util';
import elliptic from 'elliptic';
import b58 from 'bs58';
import { sha256 } from 'js-sha256';
import {
  encodeAddress, decodeAddress,
  mnemonicGenerate, mnemonicToMiniSecret,
  cryptoWaitReady, blake2AsHex, randomAsHex, base64Encode, base64Decode, base58Decode
} from '@polkadot/util-crypto';
import { initializeWasm, isWasmInitialized, SignatureParamsG1 } from '@docknetwork/crypto-wasm-ts';

import { DID_QUALIFIER } from './infra-ss58-verifiable/verifiable.constants';
import {
  typesBundle, BTreeSet, Codec, ServiceEndpointType, ExtrinsicError,
  CRYPTO_INFO, SIG_TYPE, HexString, IConfig_SS58, KeyPair, KeyringPair,
  BBSPlus_Params, BBSPlus_PublicKey, BBSPlus_SigSet,
  DIDSet, DidKey_SS58, PublicKey_SS58,
  VerificationRelationship,
  CRYPTO_BBS_INFO
} from './ss58.interface';
import { VerifiableCredential, VerifiablePresentation, Schema, BBSPlusPresentation } from './infra-ss58-verifiable';
import { U8aLike } from '@polkadot/util/types';

export {
  CRYPTO_INFO, SIG_TYPE, HexString, IConfig_SS58, KeyPair, KeyringPair,
  BBSPlus_Params, BBSPlus_PublicKey, BBSPlus_SigSet,
  DIDSet, DidKey_SS58, PublicKey_SS58, Schema,
  VerificationRelationship, VerifiableCredential, VerifiablePresentation, BBSPlusPresentation
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
  registryModule: InfraSS58_Revocation;
  trustModule: InfraSS58_TrustedEntity;

  private constructor() {}

  static async createAsync(conf: IConfig_SS58): Promise<InfraSS58> {
    if (!isWasmInitialized()) await initializeWasm()
    return await new InfraSS58().initApi(conf)
  }
  static async createNewSS58DIDSet(
    networkId: string,
    cryptoInfo: CRYPTO_INFO = CRYPTO_INFO.ED25519,
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

  static async BBSPlus_createNewSigSet(controller: string, messageCounter = 1, label?: string): Promise<BBSPlus_SigSet> {
    if (!isWasmInitialized()) await initializeWasm()
    const params = InfraSS58.BBSPlus_createSigParamsWithLabel(messageCounter, label)
    const keyPair = CRYPTO_BBS_INFO.LDKeyClass.generate({ params, controller })
    const publicKey = InfraSS58.BBSPlus_createSigPublicKey(keyPair.publicKeyBuffer)
    return { params, publicKey, messageCounter, label, keyPair }
  }
  static BBSPlus_changeSigParamMessageCounter(sigParam: SignatureParamsG1, messageCounter: number): SignatureParamsG1 {
    return sigParam.adapt(messageCounter)
  }
  static BBSPlus_createSigParamsWithLabel(messageCounter: number, label?: string): SignatureParamsG1 {
    return label ?
      SignatureParamsG1.generate(messageCounter, stringToU8a(label)) :
      SignatureParamsG1.generate(messageCounter, stringToU8a('DockBBS+Signature2022'))
  }

  static BBSPlus_createSigPublicKey(publicKey: Uint8Array, params: any = undefined): BBSPlus_PublicKey {
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
      bytes: u8aToHex(publicKey),
      paramsRef,
      curveType: CRYPTO_BBS_INFO.CURVE_TYPE
    };
  }
  public getKeyDoc(id, did, type, keypair) {
    return {
      id: id || `${did}#keys-1`,
      controller: did,
      type,
      keypair
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
    this.cryptoInfo = conf.cryptoInfo ?? CRYPTO_INFO.ED25519;
    await cryptoWaitReady();
    this.keyringModule = new Keyring({ type: this.cryptoInfo.CRYPTO_TYPE || CRYPTO_INFO.ED25519.CRYPTO_TYPE });
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
    this.registryModule = new InfraSS58_Revocation(this);
    this.trustModule = new InfraSS58_TrustedEntity(this);
    if (!isWasmInitialized()) await initializeWasm()
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
    // if (cryptoInfo.CRYPTO_TYPE === 'ecdsa') {
    //   return secp256k1.genKeyPair({ entropy: seed });
    // } else {
    return InfraSS58.getKeyringPairFromUri(seed, cryptoInfo);
    // }
  }
  static async getKeyringPairFromUri(uri, cryptoInfo?: CRYPTO_INFO): Promise<KeyringPair> {
    const cryptoType = cryptoInfo?.CRYPTO_TYPE || CRYPTO_INFO.ED25519.CRYPTO_TYPE
    const keyringModule = new Keyring({ type: cryptoType });
    await cryptoWaitReady();
    return keyringModule.addFromUri(uri, undefined, cryptoType);

  }
  static ss58addrToDID(networkId: string, addr: string) { return `${DID_QUALIFIER}${networkId}:${addr}` }
  static keyPairToDID(networkId: string, keyPair: KeyPair) {
    if ((keyPair as KeyringPair).type)
      return InfraSS58.ss58addrToDID(networkId, (keyPair as KeyringPair).address)
    // return `${DID_QUALIFIER}${networkId}:${encodeAddress(`0x${(keyPair as elliptic.ec.KeyPair).getPublic(true, 'hex').slice(0, 64)}`)}`;

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
    // if (sigType === CRYPTO_INFO.Secp256k1.SIG_TYPE) {
    //   return { [sigType]: this.signPrehashed(stateMessage, keyPair) }
    // } else
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
          type: 'Ed25519VerificationKey2018',// offchain DID에서 구분 불가. 표준 타입인 ED25519로 
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
            typ = CRYPTO_INFO.SR25519.KEY_NAME;
            publicKeyRaw = pk.asSr25519.value;
          } else if (pk.isEd25519) {
            typ = CRYPTO_INFO.ED25519.KEY_NAME;
            publicKeyRaw = pk.asEd25519.value;
            // } else if (pk.isSecp256k1) {
            //   typ = CRYPTO_INFO.Secp256k1.KEY_NAME;
            //   publicKeyRaw = pk.asSecp256k1.value;
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
            curveType: pk.curveType.isBls12381 ? CRYPTO_BBS_INFO.CURVE_TYPE : null,
            paramsRef: pr ? [u8aToHex(pr[0]), pr[1].toNumber()] : null,
          };
        }
        let currentIter = 0;
        for (const r of resp) {
          // The gaps in `keyId` might correspond to removed keys
          if (r.isSome) {
            // Don't care about signature params for now
            const pkObj = createPublicKeyObjFromChainResponse(r.unwrap());
            if (pkObj.curveType !== CRYPTO_BBS_INFO.CURVE_TYPE) {
              throw new Error(`Curve type should have been Bls12381 but was ${pkObj.curveType}`);
            }
            const keyIndex = queryKeys[currentIter][1];
            keys.push([keyIndex, CRYPTO_BBS_INFO.BBSDockVerKeyName, hexToU8a(pkObj.bytes)]);
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

  public getKeyDoc() {
    return this.that.getKeyDoc(`${this.did}#keys-1`, this.did, this.that.cryptoInfo.KEY_NAME, this.keyPairs[0])
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
        curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
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
        curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
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
      curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
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
  public async registerRegistry(id: HexString, addOnly = false) {
    if (!this.policyOwner || this.policyOwner.length < 1) { this.addPolicyOwner() }
    const addReg = { id, newRegistry: { policy: this.getPolicyOwner(), addOnly } };
    const tx = this.that.api.tx.revoke.newRegistry(addReg);
    return this.that.signAndSend(tx, false, {});
  }

  public async revokeCredential(registryId, revId) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);

    const revoke = { registryId, revokeIds: [revId] };
    const Revoke = { data: revoke, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { Revoke }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]];
    const tx = this.that.api.tx.revoke.revoke(revoke, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async unrevokeCredential(registryId, revId) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);

    const unrevoke = { registryId, revokeIds: [revId] };
    const UnRevoke = { data: unrevoke, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { UnRevoke }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]];
    const tx = this.that.api.tx.revoke.unrevoke(unrevoke, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async unregisterRegistry(registryId) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);

    const removal = { registryId };
    const RemoveRegistry = { data: removal, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveRegistry }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]];
    const tx = this.that.api.tx.revoke.removeRegistry(removal, proof);
    return this.that.signAndSend(tx, false, {});
  }
  public async getRegistry(registryID) {
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

class InfraSS58_TrustedEntity {
  private owners: string[];


  constructor(private that: InfraSS58) {
    this.owners = [];
  }
  public createNewAuthorizerId(): HexString {
    return randomAsHex(32);
  }
  public getRevokeId(vcId) {
    return blake2AsHex(vcId, 256);
  }
  public async registerAuthorizer(id: HexString, addOnly = false) {
    if (!this.owners || this.owners.length < 1) { this.addPolicyOwner() }
    const addAuthorizer = { id, newAuthorizer: { policy: this.getPolicyowner(), addOnly } };
    const tx = this.that.api.tx.trustedEntity.newAuthorizer(addAuthorizer);
    return this.that.signAndSend(tx, false, {});
  }


  public async unregisterAuthorizer(authorizerId) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    const removal = { authorizerId };
    const RemoveAuthorizer = { data: removal, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveAuthorizer }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.removeAuthorizer(removal, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async addIssuer(authorizerId, issuerDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(issuerDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const AddIssuer = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { AddIssuer }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.addIssuer(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async removeIssuer(authorizerId, issuerDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(issuerDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const RemoveIssuer = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveIssuer }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.removeIssuer(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async addVerifier(authorizerId, verifierDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(verifierDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const AddVerifier = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { AddVerifier }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.addVerifier(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async removeVerifier(authorizerId, verifierDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(verifierDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const RemoveVerifier = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveVerifier }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.removeVerifier(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async getAuthorizer(authorizerId) {
    const resp = await this.that.api.query.trustedEntity.authorizers(authorizerId);
    if (resp.isNone) {
      throw new Error(`Could not find Authorizer: ${authorizerId}`);
    }
    return resp.unwrap();
  }
  public async getIssuers(authorizerId, issuerId) {
    const resp = await this.that.api.query.trustedEntity.issuers(authorizerId, InfraSS58.didToHex(issuerId));
    if (resp.isNone) {
      throw new Error(`Could not find issuers: ${issuerId}`);
    }
    return resp.unwrap();
  }
  public async getVerifiers(authorizerId, verifierId) {
    const resp = await this.that.api.query.trustedEntity.verifiers(authorizerId, InfraSS58.didToHex(verifierId));
    if (resp.isNone) {
      throw new Error(`Could not find issuers: ${verifierId}`);
    }
    return resp.unwrap();
  }

  public getPolicyowner() {
    return {
      OneOf: this.owners.sort(),
    }
  }
  public addPolicyOwner(ownerDID?: string) {
    ownerDID ??= this.that.didModule.did
    this.owners.push(InfraSS58.didToHex(ownerDID))
  }
}
