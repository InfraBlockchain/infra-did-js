import { sha256 } from 'js-sha256';
import CustomLinkedDataSignature from './custom-linkeddatasignature';
import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';
import EcdsaSecp256k1VerificationKey2019 from './EcdsaSecp256k1VerificationKey2019';

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
      type: 'EcdsaSecp256k1Signature2019',
      LDKeyClass: EcdsaSecp256k1VerificationKey2019,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'ES256K',
      signer: signer || EcdsaSecp256k1Signature2019.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = 'EcdsaSecp256k1VerificationKey2019';
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
