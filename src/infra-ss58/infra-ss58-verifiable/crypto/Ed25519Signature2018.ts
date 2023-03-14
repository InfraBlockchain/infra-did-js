import { CRYPTO_INFO } from '../../ss58.interface';
import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';
import CustomLinkedDataSignature from './custom-linkeddatasignature';

export default class Ed25519Signature2018 extends CustomLinkedDataSignature {
  requiredKeyType: string;

  constructor({
    keypair, verificationMethod, verifier, signer,
  }: any = {}) {
    super({
      type: CRYPTO_INFO.ED25519.SIG_NAME,
      LDKeyClass: CRYPTO_INFO.ED25519.LDKeyClass,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'EdDSA',
      signer: signer || CRYPTO_INFO.ED25519.SIG_CLS.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = CRYPTO_INFO.ED25519.KEY_NAME;
  }

  static signerFactory(keypair, verificationMethod) {
    return {
      id: verificationMethod,
      async sign({ data }) {
        return keypair.sign(data);
      },
    };
  }
}
