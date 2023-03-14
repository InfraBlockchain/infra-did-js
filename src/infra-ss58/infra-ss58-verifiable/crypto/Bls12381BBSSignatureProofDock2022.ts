import { BBSPlusPublicKeyG2, } from '@docknetwork/crypto-wasm-ts';
import { Presentation } from '@docknetwork/crypto-wasm-ts/lib/anonymous-credentials/presentation';
import b58 from 'bs58';

import CustomLinkedDataSignature from './custom-linkeddatasignature';
import { hexToU8a } from '@polkadot/util';
import { CRYPTO_BBS_INFO } from '../../ss58.interface';
import { DEFAULT_CONTEXT_V1_URL } from '../verifiable.constants';


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
              type: CRYPTO_BBS_INFO.BBSSigDockSigName,
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
      type: CRYPTO_BBS_INFO.BBSSigProofDockSigName,
      LDKeyClass: CRYPTO_BBS_INFO.LDKeyClass,
      contextUrl: DEFAULT_CONTEXT_V1_URL,
      alg: CRYPTO_BBS_INFO.BBSSigProofDockSigName,
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
      type: CRYPTO_BBS_INFO.BBSSigProofDockSigName,
    };
    this.proofType = [
      CRYPTO_BBS_INFO.BBSSigProofDockSigName,
      `sec:${CRYPTO_BBS_INFO.BBSSigProofDockSigName}`,
      `https://w3id.org/security#${CRYPTO_BBS_INFO.BBSSigProofDockSigName}`,
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
    return CRYPTO_BBS_INFO.SIG_CLS.getVerificationMethod({ proof, documentLoader });
  }

  ensureSuiteContext() {
    // no-op
  }
}

