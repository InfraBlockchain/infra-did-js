import Ed25519VerificationKey2020 from './Ed25519VerificationKey2020';
import CustomLinkedDataSignature from './custom-linkeddatasignature';

export default class Ed25519Signature2020 extends CustomLinkedDataSignature {
  requiredKeyType: string;

  constructor({
    keypair, verificationMethod, verifier, signer,
  }: any = {}) {
    super({
      type: 'Ed25519Signature2020',
      LDKeyClass: Ed25519VerificationKey2020,
      contextUrl: `https://w3id.org/security/suites/ed25519-2020/v1`, //DEFAULT_CONTEXT_V1_URL
      alg: 'EdDSA',
      signer: signer || Ed25519Signature2020.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = 'Ed25519VerificationKey2020';
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
