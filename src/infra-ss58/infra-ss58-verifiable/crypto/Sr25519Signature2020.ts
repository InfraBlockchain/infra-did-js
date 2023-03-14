import { CRYPTO_INFO } from '../../ss58.interface';
import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';
import CustomLinkedDataSignature from './custom-linkeddatasignature';

export default class Sr25519Signature2020 extends CustomLinkedDataSignature {
  requiredKeyType: string;
  /**
   * Creates a new Sr25519Signature2020 instance
   * @constructor
   * @param {object} config - Configuration options
   */
  constructor({
    keypair, verificationMethod, verifier, signer,
  }: any = {}) {
    super({
      type: CRYPTO_INFO.SR25519.SIG_NAME,//Sr25519SigName,
      LDKeyClass: CRYPTO_INFO.SR25519.LDKeyClass,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'EdDSA',
      signer: signer || CRYPTO_INFO.SR25519.SIG_CLS.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = CRYPTO_INFO.SR25519.KEY_NAME;
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
        return keypair.sign(data);
      },
    };
  }
}
