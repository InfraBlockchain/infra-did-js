import b58 from 'bs58';
import * as base64 from '@juanelas/base64';
import { u8aToU8a } from '@polkadot/util';
import { sha256 } from 'js-sha256';
import elliptic from 'elliptic';
import { hexToUint8Array } from 'infrablockchain-js/dist/infrablockchain-js-serialize';
const EC = elliptic.ec;
const secp256k1Curve = new EC('secp256k1');
import { CRYPTO_INFO } from '../../ss58.interface';

export default class EcdsaSecp256k1VerificationKey2019 {
  publicKey: Uint8Array;
  constructor(publicKey) {
    this.publicKey = u8aToU8a(publicKey);
  }

  /**
   * Construct the public key object from the verification method
   * @param verificationMethod
   * @returns {EcdsaSecp256k1VerificationKey2019}
   */
  static from(verificationMethod) {
    if (!verificationMethod.type || verificationMethod.type.indexOf(CRYPTO_INFO.Secp256k1.KEY_NAME) === -1) {
      throw new Error(`verification method should have type ${CRYPTO_INFO.Secp256k1.KEY_NAME} - got: ${verificationMethod.type}`);
    }

    if (verificationMethod.publicKeyHex) {
      return new this(hexToUint8Array(verificationMethod.publicKeyHex));
    }

    if (verificationMethod.publicKeyBase58) {
      return new this(b58.decode(verificationMethod.publicKeyBase58));
    }

    if (verificationMethod.publicKeyBase64) {
      return new this(base64.decode(verificationMethod.publicKeyBase64));
    }

    throw new Error(`Unsupported signature encoding for ${CRYPTO_INFO.Secp256k1.KEY_NAME}`);
  }

  /**
   * Construct the verifier factory that has the verify method using the current public key
   * @returns {object}
   */
  verifier() {
    return EcdsaSecp256k1VerificationKey2019.verifierFactory(this.publicKey);
  }

  /**
   * Verifier factory that returns the object with the verify method
   * @param publicKey
   * @returns {object}
   */
  static verifierFactory(publicKey) {
    return {
      async verify({ data, signature }) {
        const hash = sha256.digest(data);
        return secp256k1Curve.verify(hash, signature, publicKey);
      },
    };
  }
}
