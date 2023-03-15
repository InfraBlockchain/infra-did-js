import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';
import Ed25519VerificationKey2018 from './Ed25519VerificationKey2018';
import CustomLinkedDataSignature from './custom-linkeddatasignature';

export default class Ed25519Signature2018 extends CustomLinkedDataSignature {
  requiredKeyType: string;

  constructor({
    keypair, verificationMethod, verifier, signer,
  }: any = {}) {
    super({
      type: 'Ed25519Signature2018',
      LDKeyClass: Ed25519VerificationKey2018,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'EdDSA',
      signer: signer || Ed25519Signature2018.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = 'Ed25519VerificationKey2018';
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
