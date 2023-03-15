import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';
import Sr25519VerificationKey2020 from './Sr25519VerificationKey2020';
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
      type: 'Sr25519Signature2020',
      LDKeyClass: Sr25519VerificationKey2020,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'EdDSA',
      signer: signer || Sr25519Signature2020.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = 'Sr25519VerificationKey2020';
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
