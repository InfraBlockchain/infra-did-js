import { sha256 } from 'js-sha256';
import CustomLinkedDataSignature from './custom-linkeddatasignature';
import { CRYPTO_INFO } from '../../ss58.interface';
import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';

export default class EcdsaSecp256k1Signature2019 extends CustomLinkedDataSignature {
  requiredKeyType: string;
  /**
   * Creates a new EcdsaSepc256k1Signature2019 instance
   * @constructor
   * @param {object} config - Configuration options
   */
  constructor({
    keypair, verificationMethod, verifier, signer,
  }: any = {}) {
    super({
      type: CRYPTO_INFO.Secp256k1.SIG_NAME,
      LDKeyClass: CRYPTO_INFO.Secp256k1.LDKeyClass,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'ES256K',
      signer: signer || CRYPTO_INFO.Secp256k1.SIG_CLS.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = CRYPTO_INFO.Secp256k1.KEY_NAME;
  }

  /**
   * Generate object with `sign` method
   * @param keypair
   * @returns {object}
   */
  static signerFactory(keypair, verificationMethod) {
    return {
      id: verificationMethod,
      async sign({ data }) {
        const hash = sha256.digest(data);
        return new Uint8Array(keypair.sign(hash).toDER());
      },
    };
  }
}
