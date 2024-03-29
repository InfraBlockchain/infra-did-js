import b58 from 'bs58';
import * as base64 from '@juanelas/base64';
import { u8aToHex, u8aToU8a } from '@polkadot/util';
import { signatureVerify } from '@polkadot/util-crypto/signature';
export default class Ed25519VerificationKey2020 {
  publicKey: Uint8Array;
  constructor(publicKey) {
    this.publicKey = u8aToU8a(publicKey);
  }

  static from(verificationMethod) {
    if (!verificationMethod.type || verificationMethod.type.indexOf('Ed25519VerificationKey2020') === -1) {
      throw new Error(`verification method should have type ${'Ed25519VerificationKey2020'} - got: ${verificationMethod.type}`);
    }
    if (verificationMethod.publicKeyMultibase) {
      const prefix = verificationMethod.publicKeyMultibase.toString().subString(0, 1);
      const publicKeyEncoded = verificationMethod.publicKeyMultibase.toString().subString(1);
      switch (prefix) {
        case 'U': case 'M': case 'u': case 'm':  // base64 with url or pad or both
          return new this(base64.decode(publicKeyEncoded.replace(/=/g, '')));
        case 'z':// base58btc
          return new this(b58.decode(publicKeyEncoded));
        default:
          throw new Error(`Currently, only base58btc and base64 (with url or pad or both) are supported.`);
      }
    }
    throw new Error(`Unsupported signature encoding for 'Ed25519VerificationKey2020'`);
  }

  /**
   * Construct the verifier factory that has the verify method using the current public key
   * @returns {object}
   */
  verifier() {
    return Ed25519VerificationKey2020.verifierFactory(this.publicKey);
  }

  /**
   * Verifier factory that returns the object with the verify method
   * @param publicKey
   * @returns {object}
   */
  static verifierFactory(publicKey) {
    return {
      async verify({ data, signature }) {
        const pk = u8aToHex(publicKey);
        return signatureVerify(data, signature, pk).isValid;
      },
    };
  }
}
