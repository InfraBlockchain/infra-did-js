import b58 from 'bs58';
import * as base64 from '@juanelas/base64';
import { u8aToHex, u8aToU8a, hexToU8a } from '@polkadot/util';
import { signatureVerify } from '@polkadot/util-crypto/signature';
import { CRYPTO_INFO } from '../../ss58.interface';
export default class Ed25519VerificationKey2018 {
  publicKey: Uint8Array;
  constructor(publicKey) {
    this.publicKey = u8aToU8a(publicKey);
  }

  static from(verificationMethod) {
    if (!verificationMethod.type || verificationMethod.type.indexOf(CRYPTO_INFO.ED25519.KEY_NAME) === -1) {
      throw new Error(`verification method should have type ${CRYPTO_INFO.ED25519.KEY_NAME} - got: ${verificationMethod.type}`);
    }

    if (verificationMethod.publicKeyHex) {
      return new this(hexToU8a(verificationMethod.publicKeyHex));
    }
    if (verificationMethod.publicKeyBase58) {
      return new this(b58.decode(verificationMethod.publicKeyBase58));
    }

    if (verificationMethod.publicKeyBase64) {
      return new this(base64.decode(verificationMethod.publicKeyBase64));
    }
    throw new Error(`Unsupported signature encoding for ${CRYPTO_INFO.ED25519.KEY_NAME}`);
  }

  /**
   * Construct the verifier factory that has the verify method using the current public key
   * @returns {object}
   */
  verifier() {
    return Ed25519VerificationKey2018.verifierFactory(this.publicKey);
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
