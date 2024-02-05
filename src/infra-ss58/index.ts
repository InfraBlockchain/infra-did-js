import b58 from 'bs58';

import { HttpProvider } from '@polkadot/rpc-provider';
import { hexToU8a } from '@polkadot/util/hex/toU8a';
import { stringToU8a } from '@polkadot/util/string/toU8a';
import { stringToHex } from '@polkadot/util/string/toHex';
import { u8aToHex } from '@polkadot/util/u8a/toHex';
import { ApiPromise, Keyring, WsProvider } from '@polkadot/api';
import { encodeAddress, decodeAddress, mnemonicGenerate, mnemonicToMiniSecret, cryptoWaitReady } from '@polkadot/util-crypto';

import { BBSPlusSignatureParamsG1, initializeWasm, isWasmInitialized } from '@docknetwork/crypto-wasm-ts';

import { DID_QUALIFIER } from './infra-ss58-verifiable/verifiable.constants';
import { InfraSS58_DID, InfraSS58_BBS, InfraSS58_BLOB, InfraSS58_Revocation, InfraSS58_TrustedEntity } from './modules';
import {
  typesBundle, ExtrinsicError,
  CRYPTO_INFO, SIG_TYPE, HexString, IConfig_SS58, KeyringPair,
  BBSPlus_Params, BBSPlus_PublicKey, BBSPlus_SigSet,
  DIDSet, DidKey_SS58, PublicKey_SS58,
  VerificationRelationship,
  CRYPTO_BBS_INFO,
  PublicJwk_ED,
  PrivateJwk_ED, Codec, BTreeSet, ServiceEndpointType
} from './ss58.interface';

export { CryptoHelper } from './derived/crypto.helper';
export { VerifiableCredential, VerifiablePresentation, Schema, BBSPlusPresentation } from './infra-ss58-verifiable';
export {
  typesBundle, ExtrinsicError, CRYPTO_BBS_INFO, PublicJwk_ED, PrivateJwk_ED,
  CRYPTO_INFO, SIG_TYPE, HexString, IConfig_SS58, KeyringPair,
  BBSPlus_Params, BBSPlus_PublicKey, BBSPlus_SigSet,
  DIDSet, DidKey_SS58, PublicKey_SS58, ServiceEndpointType,
  VerificationRelationship, Codec, BTreeSet, DID_QUALIFIER
}

export class InfraSS58 {
  api!: any;

  get isConnected(): boolean {
    return this.api && this.api.isConnected || false;
  }
  private address!: string;
  networkId!: string;
  accountKeyPair: KeyringPair;
  cryptoInfo: CRYPTO_INFO;
  controllerDID: string;
  controllerKeyPair: KeyringPair;
  keyringModule: Keyring;
  didModule: InfraSS58_DID;
  bbsModule: InfraSS58_BBS;
  blobModule: InfraSS58_BLOB;
  registryModule: InfraSS58_Revocation;
  trustModule: InfraSS58_TrustedEntity;

  private constructor() { }

  static async createAsync(conf: IConfig_SS58): Promise<InfraSS58> {
    if (!isWasmInitialized()) await initializeWasm()
    return await new InfraSS58().initApi(conf)
  }
  static async createNewSS58DIDSet(
    networkId: string,
    cryptoInfo: CRYPTO_INFO = CRYPTO_INFO.ED25519_2018,
    seed?: HexString,
    verRels = new VerificationRelationship(),
  ): Promise<DIDSet> {
    seed ??= u8aToHex(mnemonicToMiniSecret(mnemonicGenerate()));
    const keyPair = await InfraSS58.getKeyPairFromSeed(seed, cryptoInfo);
    const publicKey = PublicKey_SS58.fromKeyringPair(keyPair);
    const did = InfraSS58.keyPairToDID(networkId, keyPair);
    const didKey = new DidKey_SS58(publicKey, verRels);
    const keyPairJWK = await InfraSS58.generateKeyPairJWK(publicKey.toJSON()[cryptoInfo.SIG_TYPE], seed)
    return { did, didKey, keyPair, publicKey, verRels, cryptoInfo, seed, keyPairJWK };
  }
  static async generateKeyPairJWK(publicKeyHex: HexString | Uint8Array, seed: HexString | Uint8Array): Promise<{ publicJwk: PublicJwk_ED, privateJwk: PrivateJwk_ED }> {
    const privateKeyBytes = (typeof seed === 'string') ? hexToU8a(seed) : seed;
    const publicKeyBytes = (typeof publicKeyHex === 'string') ? hexToU8a(publicKeyHex) : publicKeyHex;
    const d = Buffer.from(privateKeyBytes).toString('base64url');
    const x = Buffer.from(publicKeyBytes).toString('base64url');
    const publicJwk: PublicJwk_ED = {
      alg: 'EdDSA',
      kty: 'OKP',
      crv: 'Ed25519',
      x
    };
    const privateJwk: PrivateJwk_ED = { ...publicJwk, d };
    return { publicJwk, privateJwk };
  }
  static async BBSPlus_createNewSigSet(controller: string, messageCounter = 1, label?: string): Promise<BBSPlus_SigSet> {
    if (!isWasmInitialized()) await initializeWasm()
    const params = InfraSS58.BBSPlus_createSigParamsWithLabel(messageCounter, label)
    const keyPair = CRYPTO_BBS_INFO.LDKeyClass.generate({ params, controller })
    const publicKey = InfraSS58.BBSPlus_createSigPublicKey(keyPair.publicKeyBuffer)
    return { params, publicKey, messageCounter, label, keyPair }
  }
  static BBSPlus_changeSigParamMessageCounter(sigParam: BBSPlusSignatureParamsG1, messageCounter: number): BBSPlusSignatureParamsG1 {
    return sigParam.adapt(messageCounter)
  }
  static BBSPlus_createSigParamsWithLabel(messageCounter: number, label?: string): BBSPlusSignatureParamsG1 {
    return label ?
      BBSPlusSignatureParamsG1.generate(messageCounter, hexToU8a(label)) :
      BBSPlusSignatureParamsG1.generate(messageCounter, stringToU8a('DockBBS+Signature2022'))
  }

  static BBSPlus_createSigPublicKey(publicKey: Uint8Array, params: any = undefined): BBSPlus_PublicKey {
    let paramsRef: any = undefined;
    if (params) {
      if (!(typeof params === 'object' && params instanceof Array && params.length === 2)) {
        throw new Error('Reference should be an array of 2 items');
      }
      if (typeof params[1] !== 'number') {
        throw new Error(`Second item of reference should be a number but was ${params[1]}`);
      }
      const hexDID = InfraSS58.didToHexPk(params[0])
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
    this.cryptoInfo = conf.cryptoInfo ?? CRYPTO_INFO.ED25519_2018;
    await cryptoWaitReady();
    this.keyringModule = new Keyring({ type: this.cryptoInfo.CRYPTO_TYPE || CRYPTO_INFO.ED25519_2018.CRYPTO_TYPE });
    this.networkId = conf.networkId;
    this.address = conf.address;
    if (this.address && this.address.indexOf('wss://') === -1 && this.address.indexOf('https://') === -1) {
      console.warn(`WARNING: Using non-secure endpoint: ${this.address}`);
    }
    const isWebsocket = this.address && this.address.indexOf('http') === -1;
    const provider = isWebsocket ? new WsProvider(this.address) : new HttpProvider(this.address);
    const apiOptions = {
      provider,
      types: {
        SystemTokenId: {
          paraId: "Compact<u32>",
          palletId: "Compact<u32>",
          assetId: "Compact<u32>"
        },
      },
      signedExtensions: {
        ChargeSystemToken: {
          extrinsic: {
            tip: 'Compact<u128>',
            systemTokenId: 'Option<SystemTokenId>',
            voteCandidate: 'Option<AccountId32>',
          },
          payload: {}
        }
      },
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

    this.didModule = await InfraSS58_DID.createAsync(conf, this, await InfraSS58.createNewSS58DIDSet(conf.networkId, conf.cryptoInfo, conf.seed, conf.verRels));
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
  static didToHexPk(did: string): HexString {
    const { id: ss58Addr } = InfraSS58.splitDID(did);
    return u8aToHex(decodeAddress(ss58Addr));
  }
  didToHexPk(did: string): HexString {
    const { id: ss58Addr } = InfraSS58.splitDID(did);
    return u8aToHex(decodeAddress(ss58Addr));
  }
  static hexPkToDid(pk: HexString, networkId = 'space') {
    const ss58Addr = encodeAddress(pk)
    return InfraSS58.ss58addrToDID(networkId, ss58Addr)
  }
  hexPkToDid(pk: HexString, networkId = 'space') {
    const ss58Addr = encodeAddress(pk)
    return InfraSS58.ss58addrToDID(networkId, ss58Addr)
  }
  static async getKeyPairFromSeed(seed: HexString, cryptoInfo: CRYPTO_INFO = CRYPTO_INFO.ED25519_2018): Promise<KeyringPair> {
    return InfraSS58.getKeyringPairFromUri(seed, cryptoInfo.CRYPTO_TYPE);
  }
  static async getKeyringPairFromUri(uri, cryptoInfo: 'sr25519' | 'ed25519' = 'ed25519'): Promise<KeyringPair> {
    const cryptoType = cryptoInfo || CRYPTO_INFO.ED25519_2018.CRYPTO_TYPE
    const keyringModule = new Keyring({ type: cryptoType });
    await cryptoWaitReady();
    return keyringModule.addFromUri(uri, undefined, cryptoType);
  }

  static ss58addrToDID(networkId: string, addr: string): string { return `${DID_QUALIFIER}${networkId}:${addr}` }
  static keyPairToDID(networkId: string, keyPair: KeyringPair): string {
    return InfraSS58.ss58addrToDID(networkId, (keyPair.address));
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
  protected getSig(sigType: SIG_TYPE, keyPair, stateMessage) {
    return { [sigType]: u8aToHex(keyPair.sign(stateMessage)) }
  }

  public getDIDSig(did: string, sigType: SIG_TYPE, keyPair: KeyringPair, stateMessage, keyId = 1) {
    return {
      did: InfraSS58.didToHexPk(did),
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
        let unsubFunc = () => { };
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

    const qualifier = InfraSS58.splitDID(did).qualifier;
    const hexId = InfraSS58.didToHexPk(did);
    let didDetails
    try {
      didDetails = await this.getOnchainDIDDetail(hexId);
    } catch {
      return InfraSS58.defaultDocuments(did);
    }
    const attests = await this.api.query.attest.attestations(hexId);
    // const ATTESTS_IRI = attests.iri.isSome ? u8aToString(hexToU8a(attests.iri.toString())) : null;
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
    let extraKeyId = 0
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
          const index = i.toNumber() + extraKeyId;
          const pk = dk.publicKey;
          const pkObj = pk.toJSON();
          if (pkObj.ed25519) {
            const publicKeyRaw = hexToU8a(pkObj.ed25519);
            keys.push(
              [index, CRYPTO_INFO.ED25519_2018.KEY_NAME, publicKeyRaw],
              [index + 1, CRYPTO_INFO.ED25519_2020.KEY_NAME, publicKeyRaw],
              [index + 2, CRYPTO_INFO.ED25519_JWK.KEY_NAME, publicKeyRaw],
              [index + 3, CRYPTO_INFO.MULTIKEY.KEY_NAME, publicKeyRaw]
            );
          } else {
            throw new Error(`Cannot parse public key ${pk}`);
          }

          const vr = new VerificationRelationship(dk.verRels.toNumber());
          if (vr.isAuthentication()) authn.push(index, index + 1, index + 2, index + 3);
          if (vr.isAssertion()) assertion.push(index, index + 1, index + 2, index + 3);
          if (vr.isCapabilityInvocation()) capInv.push(index, index + 1, index + 2, index + 3);
          if (vr.isKeyAgreement()) keyAgr.push(index, index + 1, index + 2, index + 3);
          extraKeyId += 3;
        }
      });
    }

    if (getBbsPlusSigKeys) {
      if (didDetails.lastKeyId > keys.length - extraKeyId) {
        const possibleBbsPlusKeyIds = new Set();
        for (let i = 1; i <= didDetails.lastKeyId; i++) {
          possibleBbsPlusKeyIds.add(i);
        }
        for (const [i, typ] of keys) {
          if (typ === CRYPTO_INFO.ED25519_2018.KEY_NAME) { possibleBbsPlusKeyIds.delete(i); }
        }

        const queryKeys: any[] = [];
        for (const k of possibleBbsPlusKeyIds) {
          queryKeys.push([hexId, k]);
        }
        const resp = await this.api.query.offchainSignatures.publicKeys.multi(queryKeys);
        function createPublicKeyObjFromChainResponse(pk) {
          const pr = (pk.paramsRef) ? pk.paramsRef.unwrap() : null
          const pkObj = pk.toJSON();
          if (pkObj.bbs) {
            return {
              bytes: pkObj.bbs.bytes,
              curveType: pkObj.bbs.curveType === CRYPTO_BBS_INFO.CURVE_TYPE ? CRYPTO_BBS_INFO.CURVE_TYPE : null,
              paramsRef: pr ? [u8aToHex(pr[0]), pr[1].toNumber()] : null,
            };
          } else if (pkObj.bbsPlus) {
            return {
              bytes: pkObj.bbsPlus.bytes,
              curveType: pkObj.bbsPlus.curveType === CRYPTO_BBS_INFO.CURVE_TYPE ? CRYPTO_BBS_INFO.CURVE_TYPE : null,
              paramsRef: pr ? [u8aToHex(pr[0]), pr[1].toNumber()] : null,
            };
          } else {
            return {
              bytes: pkObj.ps.bytes,
              curveType: pkObj.ps.curveType === CRYPTO_BBS_INFO.CURVE_TYPE ? CRYPTO_BBS_INFO.CURVE_TYPE : null,
              paramsRef: pr ? [u8aToHex(pr[0]), pr[1].toNumber()] : null,
            };
          }
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
            const keyIndex = queryKeys[currentIter][1] + extraKeyId;
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
    const verificationMethod: any = keys.map(([index, typ, publicKeyRaw]) => {
      switch (typ) {
        case CRYPTO_INFO.ED25519_2020.KEY_NAME:
          return {
            id: `${id}#keys-${index}`,
            type: typ,
            controller: id,
            publicKeyMultibase: `z${b58.encode(publicKeyRaw)}`,
          }
        case CRYPTO_INFO.ED25519_JWK.KEY_NAME:
          return {
            id: `${id}#keys-${index}`,
            type: typ,
            controller: id,
            publicKeyJwk: {
              alg: 'EdDSA',
              kty: 'OKP',
              crv: 'Ed25519',
              kid: `keys-${index}`,
              x: Buffer.from(publicKeyRaw).toString('base64url'),
            }
          }
        case CRYPTO_INFO.MULTIKEY.KEY_NAME:
          return {
            id: `${id}#keys-${index}`,
            type: typ,
            controller: id,
            publicKeyMultibase: `z${b58.encode(publicKeyRaw)}`,
          }
        default: // Ed25519VerificationKey2018 or Bls12381G2VerificationKeyDock2022
          return {
            id: `${id}#keys-${index}`,
            type: typ,
            controller: id,
            publicKeyBase58: b58.encode(publicKeyRaw),
          }
      }
    });
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
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3c.github.io/vc-data-integrity/contexts/multikey/v1.jsonld', 'https://w3id.org/security/data-integrity/v2', 'https://digitalbazaar.github.io/ed25519-signature-2020-context/contexts/ed25519-signature-2020-v1.jsonld', 'https://w3c.github.io/vc-jws-2020/contexts/v1'],
      id,
      controller: controllers.map((c) => `${qualifier}${encodeAddress(c)}`),
      verificationMethod,
      authentication,
      assertionMethod,
      keyAgreement,
      capabilityInvocation,
      // ATTESTS_IRI,
      service,
    };
  }
  static defaultDocuments = (did: string) => {
    const { id } = InfraSS58.splitDID(did);
    const publicKey = decodeAddress(id);
    return ({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3c.github.io/vc-data-integrity/contexts/multikey/v1.jsonld', 'https://w3id.org/security/data-integrity/v2', 'https://digitalbazaar.github.io/ed25519-signature-2020-context/contexts/ed25519-signature-2020-v1.jsonld', 'https://w3c.github.io/vc-jws-2020/contexts/v1'],
      id: did,
      controller: [did],
      verificationMethod: [
        {
          id: `${did}#keys-1`,
          type: 'Ed25519VerificationKey2018',
          controller: did,
          publicKeyBase58: b58.encode(publicKey),
        },
        {
          id: `${did}#keys-2`,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyMultibase: `z${b58.encode(publicKey)}`,
        },
        {
          id: `${did}#keys-3`,
          type: 'JsonWebKey2020',
          controller: did,
          publicKeyJwk: {
            alg: 'EdDSA',
            kty: 'OKP',
            crv: 'Ed25519',
            kid: 'keys-3',
            x: Buffer.from(publicKey).toString('base64url'),
          }
        },
        {        
          id: `${did}#keys-4`,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: `z${b58.encode(publicKey)}`,
        }
      ],
      authentication: [`${did}#keys-1`, `${did}#keys-2`, `${did}#keys-3`, `${did}#keys-4`],
      assertionMethod: [`${did}#keys-1`, `${did}#keys-2`, `${did}#keys-3`, `${did}#keys-4`],
      keyAgreement: [],
      capabilityInvocation: [`${did}#keys-1`, `${did}#keys-2`, `${did}#keys-3`, `${did}#keys-4`],
      service: []
    });
  }

}



