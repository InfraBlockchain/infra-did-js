import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';
import { expandJSONLD } from '.';

const { AssertionProofPurpose } = jsigs.purposes;

export default class CredentialIssuancePurpose extends AssertionProofPurpose {
  constructor({ controller, date = undefined, maxTimestampDelta = undefined }: any = {}) {
    super({ controller, date, maxTimestampDelta });
  }
  async validate(proof, {
    document, suite, verificationMethod, documentLoader, expansionMap,
  }) {
    try {
      const result = await super.validate(proof, {
        document, suite, verificationMethod, documentLoader, expansionMap,
      });

      if (!result.valid) {
        throw result.error;
      }

      const expandedDoc = await expandJSONLD(document, {
        documentLoader,
      });

      const issuer = jsonld.getValues(expandedDoc,
        'https://www.w3.org/2018/credentials#issuer');

      if (!issuer || issuer.length === 0) {
        throw new Error('Credential issuer is required.');
      }

      if (result.controller.id !== issuer[0]['@id']) {
        throw new Error(
          'Credential issuer must match the verification method controller.',
        );
      }

      return { valid: true, error: null };
    } catch (error) {
      return { valid: false, error };
    }
  }
}
