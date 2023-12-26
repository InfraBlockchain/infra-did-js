import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';
import JsonWebKey2020 from './JsonWebKey2020';
import CustomLinkedDataSignature from './custom-linkeddatasignature';

export default class JsonWebSignature2020 extends CustomLinkedDataSignature {
  requiredKeyType: string;

  constructor({
    keypair, verificationMethod, verifier, signer,
  }: any = {}) {
    super({
      type: 'JsonWebSignature2020',
      LDKeyClass: JsonWebKey2020,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'EdDSA',
      signer: signer || JsonWebSignature2020.signerFactory(keypair, verificationMethod),
      verifier,
    });
    this.requiredKeyType = 'JsonWebKey2020';
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
