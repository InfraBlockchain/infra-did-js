import jsigs from 'jsonld-signatures';
import base58btc from 'bs58';
import base64url from 'base64url';

const MULTIBASE_BASE58BTC_HEADER = 'z';

function createJws({ encodedHeader, verifyData }) {
  const buffer = Buffer.concat([
    Buffer.from(`${encodedHeader}.`, 'utf8'),
    Buffer.from(verifyData.buffer, verifyData.byteOffset, verifyData.length),
  ]);
  return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.length);
}

function decodeBase64Url(string) {
  const buffer = base64url.toBuffer(string);
  // @ts-ignore
  return new Uint8Array(buffer.buffer, buffer.offset, buffer.length);
}


export default class CustomLinkedDataSignature extends jsigs.suites.LinkedDataSignature {
  type: any;
  LDKeyClass: any;
  signer: any;
  verifier: any;
  alg: any;

  /**
   * Creates a new CustomLinkedDataSignature instance
   * @constructor
   * @param {object} config - Configuration options
   */
  constructor(config) {
    super(config);
    this.type = config.type;
    this.LDKeyClass = config.LDKeyClass;
    this.signer = config.signer;
    this.verifier = config.verifier;
    this.alg = config.alg;
  }

  async verifySignature({ verifyData, verificationMethod, proof }) {
    let signatureBytes;
    let data = verifyData;

    const { proofValue, jws } = proof;
    if (proofValue && typeof proofValue === 'string') {
      signatureBytes = base58btc.decode(CustomLinkedDataSignature.fromJsigProofValue(proofValue));
    } else if (jws && typeof jws === 'string') { // Fallback to older jsonld-signature implementations
      const [encodedHeader, /* payload */, encodedSignature] = jws.split('.');

      let header;
      try {
        header = JSON.parse(base64url.decode(encodedHeader));
      } catch (e) {
        throw new Error(`Could not parse JWS header; ${e}`);
      }
      if (!(header && typeof header === 'object')) {
        throw new Error('Invalid JWS header.');
      }

      // confirm header matches all expectations
      if (!(header.alg === this.alg && header.b64 === false
        && Array.isArray(header.crit) && header.crit.length === 1
        && header.crit[0] === 'b64')) {
        throw new Error(
          `Invalid JWS header parameters for ${this.type}.`,
        );
      }

      signatureBytes = decodeBase64Url(encodedSignature);
      data = createJws({ encodedHeader, verifyData });
    }

    let { verifier } = this;
    if (!verifier) {
      const key = await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier();
    }
    return verifier.verify({ data, signature: signatureBytes });
  }

  async sign({ verifyData, proof }) {
    if (!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.');
    }

    let signatureBytes;
    const signature = await this.signer.sign({ data: verifyData });
    if (typeof signature === 'string') {
      // Some signers will return a string like: header..signature
      // split apart those strings to get the signature in bytes
      const signatureSplit = signature.split('.');
      const signatureEncoded = signatureSplit[signatureSplit.length - 1];
      signatureBytes = decodeBase64Url(signatureEncoded);
    } else {
      signatureBytes = signature;
    }

    return {
      ...proof,
      proofValue: CustomLinkedDataSignature.encodeProofValue(signatureBytes),
    };
  }

  static encodeProofValue(signatureBytes) {
    return MULTIBASE_BASE58BTC_HEADER + base58btc.encode(signatureBytes);
  }

  static fromJsigProofValue(proofValue) {
    if (proofValue[0] !== MULTIBASE_BASE58BTC_HEADER) {
      throw new Error('Only base58btc multibase encoding is supported.');
    }
    return proofValue.substring(1);
  }
}
