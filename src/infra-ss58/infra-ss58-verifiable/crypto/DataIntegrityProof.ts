import Ed25519MultiKey from './Ed25519MultiKey';
import CustomLinkedDataSignature from './custom-linkeddatasignature';
const DATA_INTEGRITY_CONTEXT_V2 = 'https://w3id.org/security/data-integrity/v2';
const DATA_INTEGRITY_CONTEXT_V1 = 'https://w3id.org/security/data-integrity/v1';

export default class DataIntegrityProof extends CustomLinkedDataSignature {
  requiredKeyType: string;

  constructor({
    keypair, verificationMethod, verifier, signer,
  }: any = {}) {
    super({
      type: 'DataIntegrityProof',
      LDKeyClass: Ed25519MultiKey,
      contextUrl: DATA_INTEGRITY_CONTEXT_V2,
      alg: 'EdDSA',
      signer: signer || DataIntegrityProof.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = 'Multikey';
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
