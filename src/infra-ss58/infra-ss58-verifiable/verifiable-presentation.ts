
import { VerifiableHelper } from './verifiable.interface';
import { DEFAULT_CONTEXT_V1_URL, DEFAULT_VP_TYPE } from './verifiable.constants';

import type { InfraSS58, VerifiableCredential } from '..';

export default class VerifiablePresentation extends VerifiableHelper {
  proof: any;
  id: any;
  context: string[];
  type: string[];
  credentials: never[];
  holder: any;

  constructor(id) {
    super();
    this.ensureURI(id);
    this.id = id;
    this.context = [DEFAULT_CONTEXT_V1_URL];
    this.type = [DEFAULT_VP_TYPE];
    this.credentials = [];
    this.proof = null;
  }

  static fromJSON(json) {
    const {
      verifiableCredential, id, type, ...rest
    } = json;
    const vp = new VerifiablePresentation(id);

    if (type) {
      vp.type = [];
      if (type.length !== undefined) {
        type.forEach((typeVal) => {
          vp.addType(typeVal);
        });
      } else {
        vp.addType(type);
      }
    } else {
      throw new Error('No type found in JSON object, verifiable presentations must have a type field.');
    }

    const context = rest['@context'];
    if (context) {
      vp.setContext(rest['@context']);
      delete rest['@context'];
    } else {
      throw new Error('No context found in JSON object, verifiable presentations must have a @context field.');
    }

    if (verifiableCredential) {
      if (verifiableCredential.length) {
        verifiableCredential.forEach((credential) => {
          vp.addCredential(credential);
        });
      } else {
        vp.addCredential(verifiableCredential);
      }
    }

    Object.assign(vp, rest);
    return vp;
  }

  setContext(context) {
    if (!this.isObject(context) && !Array.isArray(context)) {
      this.ensureURI(context);
    }
    this.context = context;
    return this;
  }

  addContext(context) {
    if (!this.isObject(context)) {
      this.ensureURI(context);
    }
    this.context = this.getUniqueElementsFromArray([...this.context, context], JSON.stringify);
    return this;
  }

  addType(type: string) {
    this.type = [...new Set([...this.type, type])];
    return this;
  }

  setHolder(holder) {
    this.ensureURI(holder);
    this.holder = holder;
    return this;
  }

  addCredential(credential: VerifiableCredential) {
    // let cred = credential;
    // if (credential instanceof VerifiableCredential) {
    const cred = credential.toJSON();
    // }
    this.ensureObjectWithKey(cred, 'id', 'credential');
    this.credentials = this.getUniqueElementsFromArray([...this.credentials, cred], JSON.stringify);

    return this;
  }

  toJSON() {
    const { context, credentials, ...rest } = this;
    return {
      '@context': context,
      verifiableCredential: credentials,
      ...rest,
    };
  }

  async sign(infraApi: InfraSS58, challenge, domain, compactProof = true) {
    const signedVP = await this.signPresentation(
      this.toJSON(),
      await infraApi.didModule.getKeyDoc(),
      challenge,
      domain,
      infraApi.Resolver,
      compactProof,
    );
    this.proof = signedVP.proof.pop();
    return this;
  }

  async verify(infraApi: InfraSS58, challenge, domain, compactProof = true, forceRevocationCheck = true, suite: any = []) {
    if (!this.proof) {
      throw new Error('The current VerifiablePresentation has no proof.');
    }

    return this.verifyPresentation(this.toJSON(), {
      challenge,
      domain,
      resolver: infraApi.Resolver,
      compactProof,
      forceRevocationCheck,
      revocationModule: infraApi.registryModule,
      blobModule: infraApi.blobModule,
      suite,
    });
  }
}

