import { BBSPlusPublicKeyG2, initializeWasm, isWasmInitialized } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import { stringToU8a } from '@polkadot/util';
import { VerifiableHelper, defaultDocumentLoader } from './verifiable.interface';
import { PresentationBuilder, Credential, } from '@docknetwork/crypto-wasm-ts/lib/anonymous-credentials';
import CustomLinkedDataSignature from './crypto/custom-linkeddatasignature';
import { CRYPTO_BBS_INFO } from '../ss58.interface';

export default class BBSPlusPresentation extends VerifiableHelper {
  presBuilder: PresentationBuilder;

  constructor() {
    super();
    this.presBuilder = new PresentationBuilder();
  }
  async issueCredential(keyDoc, credential, compactProof = true, documentLoader = null, purpose = null, expansionMap = null, issuerObject = null, addSuiteContext = false) {
    return await super.issueCredential(keyDoc, credential, compactProof, documentLoader, purpose, expansionMap, issuerObject, addSuiteContext)
  }
  async verifyPresentation(presentation, options: any = {}) {
    return await super.verifyPresentation(presentation, options)
  }

  addAttributeToReveal(credentialIndex, attributes: string[] = []) {
    this.presBuilder.markAttributesRevealed(credentialIndex, new Set(attributes));
  }

  addCredentialSubjectAttributeToReveal(credentialIndex, attributes: string[] = []) {
    this.addAttributeToReveal(
      credentialIndex, attributes.map(attr => `credentialSubject.${attr}`)
    )
  }

  createPresentation({ nonce, context }: any = {}): any {
    if (nonce) {
      this.presBuilder.nonce = stringToU8a(nonce);
    }
    if (context) {
      this.presBuilder.context = context;
    }
    const pres = this.presBuilder.finalize();
    return pres.toJSON();
  }


  async addCredentialToPresent(credentialLD, options: any = {}) {
    if (options.documentLoader && options.resolver) {
      throw new Error('Passing resolver and documentLoader results in resolver being ignored, please re-factor.');
    }
    if (!isWasmInitialized()) {
      await initializeWasm();
    }
    const documentLoader = options.documentLoader || defaultDocumentLoader(options.resolver);
    const document = typeof credentialLD === 'string' ? JSON.parse(credentialLD) : credentialLD;
    const { proof } = document;
    if (!proof) {
      throw new Error('BBS credential does not have a proof');
    }
    const keyDocument = await CRYPTO_BBS_INFO.SIG_CLS.getVerificationMethod({
      proof,
      documentLoader,
    });
    const pkRaw = b58.decode(keyDocument.publicKeyBase58);
    const pk = new BBSPlusPublicKeyG2(pkRaw);
    const [credential] = CRYPTO_BBS_INFO.SIG_CLS.convertCredential({ document });
    const convertedCredential = Credential.fromJSON(credential, CustomLinkedDataSignature.fromJsigProofValue(credentialLD.proof.proofValue));
    const idx = await this.presBuilder.addCredential(convertedCredential, pk);
    // Enforce revealing of verificationMethod and type. also require context and type for JSON-LD
    this.addAttributeToReveal(idx, ['@context', 'type', 'proof.type', 'proof.verificationMethod']);
    return idx;
  }

  deriveCredentials(options) {
    const presentation: any = this.createPresentation(options);
    const { credentials } = presentation.spec;
    if (credentials.length > 1) {
      throw new Error('Cannot derive from multiple credentials in a presentation');
    }

    return credentials.map((credential) => {
      if (!credential.revealedAttributes.proof) {
        throw new Error('Credential proof is not revealed, it should be');
      }

      const date = new Date().toISOString();

      return {
        ...credential.revealedAttributes,
        '@context': JSON.parse(credential.revealedAttributes['@context']),
        type: JSON.parse(credential.revealedAttributes.type),
        credentialSchema: JSON.parse(credential.schema),
        issuer: credential.revealedAttributes.issuer || credential.revealedAttributes.proof.verificationMethod.split('#')[0],
        issuanceDate: credential.revealedAttributes.issuanceDate || date,
        proof: {
          proofPurpose: 'assertionMethod',
          created: date,
          ...credential.revealedAttributes.proof,
          type: CRYPTO_BBS_INFO.BBSSigProofDockSigName,
          proofValue: presentation.proof,
          nonce: presentation.nonce,
          context: presentation.context,
          attributeCiphertexts: presentation.attributeCiphertexts,
          attributeEqualities: presentation.spec.attributeEqualities,
          version: credential.version,
        },
      };
    });
  }
}
