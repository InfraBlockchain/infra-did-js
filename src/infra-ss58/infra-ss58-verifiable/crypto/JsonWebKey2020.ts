import * as base64 from '@juanelas/base64';
import { u8aToHex, u8aToU8a } from '@polkadot/util';
import { signatureVerify } from '@polkadot/util-crypto/signature';
export default class JsonWebKey2020 {
  publicKey: Uint8Array;
  constructor(publicKey) {
    this.publicKey = u8aToU8a(publicKey);
  }

  static from(verificationMethod) {
    if (!verificationMethod.type || verificationMethod.type.indexOf('JsonWebKey2020') === -1) {
      throw new Error(`verification method should have type 'JsonWebKey2020' - got: ${verificationMethod.type}`);
    }

    if (verificationMethod.publicKeyJwk) {
      if (verificationMethod.publicKeyJwk.alg !== 'EdDSA' ||
        verificationMethod.publicKeyJwk.kty !== 'OKP' ||
        verificationMethod.publicKeyJwk.crv !== 'Ed25519') {
        throw new Error(`Currently, only Ed25519 crv are supported.`);
      }
      return new this(base64.decode(verificationMethod.publicKeyJwk.x));
    }
    if (verificationMethod.hasOwnProperty('sec:publicKeyJwk')) {
      if (verificationMethod['sec:publicKeyJwk']['@value'].alg !== 'EdDSA' ||
        verificationMethod['sec:publicKeyJwk']['@value'].kty !== 'OKP' ||
        verificationMethod['sec:publicKeyJwk']['@value'].crv !== 'Ed25519') {
        throw new Error(`Currently, only Ed25519 crv are supported.`);
      }
      return new this(base64.decode(verificationMethod['sec:publicKeyJwk']['@value'].x));
    }
    throw new Error(`Unsupported signature encoding for 'JsonWebKey2020'`);
  }

  /**
   * Construct the verifier factory that has the verify method using the current public key
   * @returns {object}
   */
  verifier() {
    return JsonWebKey2020.verifierFactory(this.publicKey);
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
        return signatureVerify(data, signature, pk);
      },
    };
  }
}
