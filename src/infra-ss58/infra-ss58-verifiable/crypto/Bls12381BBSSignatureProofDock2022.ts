import { BBSPlusPublicKeyG2, } from '@docknetwork/crypto-wasm-ts';
import { Presentation } from '@docknetwork/crypto-wasm-ts/lib/anonymous-credentials/presentation';
import b58 from 'bs58';
import CustomLinkedDataSignature from './custom-linkeddatasignature';
import { hexToU8a } from '@polkadot/util';
import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';
import Bls12381G2KeyPairDock2022 from './Bls12381G2KeyPairDock2022';
import Bls12381BBSSignatureDock2022 from './Bls12381BBSSignatureDock2022';


/*
 * Converts a derived BBS+ proof credential to the native presentation format
 */
export function convertToPresentation(document) {
  const {
    '@context': context,
    type,
    credentialSchema,
    issuer,
    issuanceDate,
    proof,
    ...revealedAttributes
  } = document;

  return {
    version: '0.0.1',
    nonce: proof.nonce,
    context: proof.context,
    spec: {
      credentials: [
        {
          version: proof.version,
          schema: JSON.stringify(credentialSchema),
          revealedAttributes: {
            proof: {
              type: 'Bls12381BBS+SignatureDock2022',
              verificationMethod: proof.verificationMethod,
            },
            '@context': JSON.stringify(context),
            type: JSON.stringify(type),
            ...revealedAttributes,
          },
        },
      ],
      attributeEqualities: proof.attributeEqualities,
    },
    attributeCiphertexts: proof.attributeCiphertexts,
    proof: proof.proofValue,
  };
}


export default class Bls12381BBSSignatureProofDock2022 extends CustomLinkedDataSignature {
  private proof: { '@context': (string | { sec: string; proof: { '@id': string; '@type': string; '@container': string; }; })[]; type: string; };
  verificationMethod: any;
  proofType: string[];

  constructor(options = {}) {
    const {
      verificationMethod,
    }: any = options;

    super({
      type: 'Bls12381BBS+SignatureProofDock2022',
      LDKeyClass: Bls12381G2KeyPairDock2022,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: 'Bls12381BBS+SignatureProofDock2022',
    });

    this.proof = {
      '@context': [
        {
          sec: 'https://w3id.org/security#',
          proof: {
            '@id': 'sec:proof',
            '@type': '@id',
            '@container': '@graph',
          },
        },
        'https://ld.dock.io/security/bbs/v1',
      ],
      type: 'Bls12381BBS+SignatureProofDock2022',
    };
    this.proofType = [
      'Bls12381BBS+SignatureProofDock2022',
      `sec:${'Bls12381BBS+SignatureProofDock2022'}`,
      `https://w3id.org/security#${'Bls12381BBS+SignatureProofDock2022'}`,
    ];

    this.verificationMethod = verificationMethod;
  }

  async verifyProof({
    proof, document, documentLoader, expansionMap,
  }) {
    try {
      const verificationMethod = await this.getVerificationMethod(
        {
          proof, document, documentLoader, expansionMap,
        },
      );

      const presentationJSON = convertToPresentation({ ...document, proof });
      const recreatedPres = Presentation.fromJSON(presentationJSON);

      const pks = [verificationMethod].map((keyDocument) => {
        const pkRaw = b58.decode(keyDocument.publicKeyBase58);
        const pkRawHex = hexToU8a(keyDocument.publicKeyHex);

        return new BBSPlusPublicKeyG2(pkRaw || pkRawHex);
      });

      if (!recreatedPres.verify(pks)) {
        throw new Error('Invalid signature');
      }

      return { verified: true, verificationMethod };
    } catch (error) {
      return { verified: false, error };
    }
  }

  /**
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   */
  async getVerificationMethod({ proof, documentLoader }: any) {
    return Bls12381BBSSignatureDock2022.getVerificationMethod({ proof, documentLoader });
  }

  ensureSuiteContext() {
    // no-op
  }
}

