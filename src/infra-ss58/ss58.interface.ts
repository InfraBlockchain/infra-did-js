import { u8aToHex } from '@polkadot/util';
import { BTreeSet } from '@polkadot/types';
import { Codec } from '@polkadot/types-codec/types';
import { KeyringPair } from '@polkadot/keyring/types';
import typesBundle from '@docknetwork/node-types';
import { KeypairG2, SignatureParamsG1 } from '@docknetwork/crypto-wasm-ts';
import elliptic from 'elliptic';
export { KeyringPair, Codec, typesBundle, BTreeSet };

export const CRYPTO_INFO = {
  SR25519: {
    CRYPTO_TYPE: 'sr25519',
    KEY_TYPE: 'Sr25519VerificationKey2020',
    SIG_TYPE: 'Sr25519',
  },
  ED25519: {
    CRYPTO_TYPE: 'ed25519',
    KEY_TYPE: 'Ed25519VerificationKey2018',
    SIG_TYPE: 'Ed25519'
  },
  Secp256k1: {
    CRYPTO_TYPE: 'ecdsa',
    KEY_TYPE: 'EcdsaSecp256k1VerificationKey2019',
    SIG_TYPE: 'Secp256k1'
  }
} as const

export type CRYPTO_INFO = typeof CRYPTO_INFO[keyof typeof CRYPTO_INFO]
export type SIG_TYPE = typeof CRYPTO_INFO.ED25519.SIG_TYPE | typeof CRYPTO_INFO.SR25519.SIG_TYPE | typeof CRYPTO_INFO.Secp256k1.SIG_TYPE

export type HexString = `0x${string}`;
export type KeyPair = KeyringPair | elliptic.ec.KeyPair;
export interface IConfig_SS58 {
  did: string;
  address: string;
  networkId: string;
  seed?: HexString; //seed or key pair required
  keyPair?: KeyPair;
  controllerDID?: string;// same role as didOwnerPrivateKey
  controllerSeed?: HexString; // alter to controllerKeyPair
  controllerKeyPair?: KeyPair; // same role as didOwnerPrivateKey
  txfeePayerAccountSeed?: HexString, // alter to txfeePayerAccountKeyPair
  txfeePayerAccountKeyPair?: KeyPair, // same role as txfeePayerAccount
  cryptoInfo?: CRYPTO_INFO;
  verRels?: VerificationRelationship;
}

export interface DIDSet {
  did: string;
  didKey: DidKey_SS58;
  keyPair: KeyPair;
  publicKey: PublicKey_SS58;
  verRels: VerificationRelationship;
  cryptoInfo: CRYPTO_INFO;
  seed: HexString;
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
  label: string | null;
}
export class PublicKey_SS58 {
  constructor(private value: HexString, private sigType: SIG_TYPE = CRYPTO_INFO.SR25519.SIG_TYPE) {
    this.value = value;
    this.sigType = sigType;
  }
  static fromKeyringPair(pair: KeyPair): PublicKey_SS58 {
    switch ((pair as KeyringPair).type) {
      case CRYPTO_INFO.ED25519.CRYPTO_TYPE:
        return new this(u8aToHex((pair as KeyringPair).publicKey), CRYPTO_INFO.ED25519.SIG_TYPE);
      case CRYPTO_INFO.SR25519.CRYPTO_TYPE:
        return new this(u8aToHex((pair as KeyringPair).publicKey), CRYPTO_INFO.SR25519.SIG_TYPE);
      case undefined:
        return new this(`0x${(pair as elliptic.ec.KeyPair).getPublic(true, 'hex')}`, CRYPTO_INFO.Secp256k1.SIG_TYPE);
      default:
        throw new Error('Not supported keyPair typs')
    }
  }
  toJSON() {
    return { [this.sigType]: this.value };
  }
}

export class DidKey_SS58 {
  constructor(private publicKey: PublicKey_SS58, private verRels?: VerificationRelationship) {
    this.verRels = verRels !== undefined ? verRels : new VerificationRelationship();
  }
  toJSON() {
    return {
      publicKey: this.publicKey.toJSON(),
      verRels: this.verRels?.value,
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
          errorMsg += `\n${section}.${method}: ${docs.join(' ')} `;
        } catch (e) {
          errorMsg += `\nError at module index: ${error.asModule.index} Error: ${error.asModule.error} `;
        }
      } else {
        const errorStr = error.toString();
        if (errorStr !== '0') {
          errorMsg += `\n${errorStr} `;
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
  setLinkedDomains() { this._value |= 0b0001; }
}