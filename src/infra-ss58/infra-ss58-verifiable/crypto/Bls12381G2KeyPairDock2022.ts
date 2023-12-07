import { hexToU8a, u8aToU8a } from '@polkadot/util';
import b58 from 'bs58';
import { stringToU8a } from '@polkadot/util/string/toU8a';

import {
  BBSPlusKeypairG2,
  BBSPlusSignatureG1,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusSignatureParamsG1,
} from '@docknetwork/crypto-wasm-ts';
import { BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES, } from '@docknetwork/crypto-wasm-ts/lib/anonymous-credentials';


const signerFactory = (key) => {
  if (!key.id) {
    return {
      async sign() {
        throw new Error('No key ID for the label.');
      },
    };
  }
  if (!key.privateKeyBuffer) {
    return {
      async sign() {
        throw new Error('No private key to sign with.');
      },
    };
  }
  return {
    async sign({ data }) {
      const msgCount = data.length;
      const sigParams = BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(msgCount, BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES);
      const signature = BBSPlusSignatureG1.generate(data, new BBSPlusSecretKey(u8aToU8a(key.privateKeyBuffer)), sigParams, false);
      return signature.value;
    },
  };
};

const verifierFactory = (key) => {
  if (!key.id) {
    return {
      async sign() {
        throw new Error('No key ID for the label.');
      },
    };
  }
  if (!key.publicKeyBuffer) {
    return {
      async verify() {
        throw new Error('No public key to verify with.');
      },
    };
  }

  return {
    async verify({ data, signature }) {
      const msgCount = data.length;
      const sigParams = BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(msgCount, BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES);
      const bbsSignature = new BBSPlusSignatureG1(u8aToU8a(signature));

      try {
        const result = bbsSignature.verify(data, new BBSPlusPublicKeyG2(u8aToU8a(key.publicKeyBuffer)), sigParams, false);
        return result.verified;
      } catch (e) {
        console.error('crypto-wasm-ts error:', e);
        return false;
      }
    },
  };
};

export default class Bls12381G2KeyPairDock2022 {
  type: string;
  id: any;
  controller: any;
  privateKeyBuffer: any;
  publicKeyBuffer: any;
  constructor(options) {
    this.type = 'Bls12381G2VerificationKeyDock2022';
    this.id = options.id;
    this.controller = options.controller;

    const { keypair } = options;

    if (keypair) {
      this.privateKeyBuffer = keypair.sk.value;
      this.publicKeyBuffer = keypair.pk.value;
    } else {
      this.privateKeyBuffer = (options.privateKeyBase58
        ? b58.decode(options.privateKeyBase58)
        : hexToU8a(options.privateKeyHex)) ?? undefined

      this.publicKeyBuffer = options.publicKeyBase58 ? b58.decode(options.publicKeyBase58) : hexToU8a(options.publicKeyHex);

    }
  }

  static async from(options) {
    return new Bls12381G2KeyPairDock2022(options);
  }

  static generate({
    seed, params, controller, id,
  }: any = {}) {
    const keypair = BBSPlusKeypairG2.generate(params || BBSPlusSignatureParamsG1.generate(10, stringToU8a('DockBBS+Signature2022')));
    return new Bls12381G2KeyPairDock2022({ keypair, controller, id });
  }

  /**
   * Returns a signer object for use with jsonld-signatures.
   *
   * @returns {{sign: Function}} A signer for the json-ld block.
   */
  signer() {
    return signerFactory(this);
  }

  /**
   * Returns a verifier object for use with jsonld-signatures.
   *
   * @returns {{verify: Function}} Used to verify jsonld-signatures.
   */
  verifier() {
    return verifierFactory(this);
  }
}
