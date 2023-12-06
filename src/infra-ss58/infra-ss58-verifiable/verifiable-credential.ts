import { DEFAULT_VC_TYPE, DEFAULT_CONTEXT_V1_URL, } from './verifiable.constants'
import { VerifiableHelper } from './verifiable.interface';

export default class VerifiableCredential extends VerifiableHelper {
  context: string[];
  type: string[];
  credentialSubject: any[];
  issuer: any;
  proof: any;
  credentialSchema: { id: any; type: any; };
  id: string;
  status: any;
  issuanceDate: string;
  expirationDate: string;

  constructor(id: string) {
    super();
    if (id) {
      this.setId(id);
    }
    this.context = [DEFAULT_CONTEXT_V1_URL];
    this.type = [DEFAULT_VC_TYPE];
    this.credentialSubject = [];
    this.setIssuanceDate(new Date().toISOString());
  }

  setId(id: string) {
    this.ensureURI(id);
    this.id = id;
    return this;
  }
  setIssuer(issuer: string) {
    this.issuer = issuer;
    return this;
  }

  setProof(proof) {
    this.proof = proof;
    return this;
  }

  setSchema(id, type = 'JsonSchemaValidator2018') {
    this.ensureURI(id);
    this.credentialSchema = {
      id, type,
    };
    return this;
  }

  async validateSchema(schema) {
    if (!this.credentialSubject) {
      throw new Error('No credential subject defined');
    }

    const expanded = await this.expandJSONLD(this.toJSON());
    return this.validateCredentialSchema(expanded, schema, this.context, undefined);
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

  addSubject(subject) {
    // if (!this.credentialSubject || this.credentialSubject.length === 0) {
    //   this.credentialSubject = subject;
    // }
    // const subjects = this.credentialSubject.length ? this.credentialSubject : this.credentialSubject;
    // this.credentialSubject = this.getUniqueElementsFromArray([...subjects, subject], JSON.stringify);
    this.credentialSubject = subject;
    return this;
  }

  setSubject(subject) {
    if (!this.isObject(subject) && !Array.isArray(subject)) {
      throw new Error('credentialSubject must be either an object or array');
    }
    this.credentialSubject = subject;
    return this;
  }

  setStatus(status) {
    this.ensureObjectWithKey(status, 'id', 'credentialStatus');
    if (!status.type) {
      throw new Error('"credentialStatus" must include a type.');
    }
    this.status = status;
    return this;
  }

  setIssuanceDate(issuanceDate: string) {
    this.ensureValidDatetime(issuanceDate);
    this.issuanceDate = issuanceDate;
    return this;
  }

  setExpirationDate(expirationDate: string) {
    this.ensureValidDatetime(expirationDate);
    this.expirationDate = expirationDate;
    return this;
  }

  toJSON() {
    const { context, status, ...rest } = this;
    Object.keys(rest).forEach(key => rest[key] === undefined ? delete rest[key] : {});

    const obj = {
      '@context': this.context,
      credentialStatus: this.status,
      ...rest
    }
    return JSON.parse(JSON.stringify(obj));
  }

  async sign(keyDoc, compactProof = true, issuerObject = null, addSuiteContext = false) {
    const signedVC = await this.issueCredential(
      keyDoc,
      this.toJSON(),
      compactProof,
      null, null, null,
      issuerObject,
      addSuiteContext,
    );
    this.setProof(signedVC.proof);
    this.issuer = signedVC.issuer;
    return this;
  }

  async verify(infraApi, compactProof = true, forceRevocationCheck = true, suite: any = [],) {
    if (!this.proof) {
      throw new Error('The current Verifiable Credential has no proof.');
    }

    return this.verifyCredential(this.toJSON(), {
      resolver: infraApi.Resolver,
      compactProof,
      forceRevocationCheck,
      revocationModule: infraApi.revocationModule,
      blobModule: infraApi.blobModule,
      suite,
    });
  }

  setFromJSON(json) {
    const subject = (json.credentialSubject || json.subject);
    if (subject) {
      const subjects = subject.length ? subject : [subject];
      subjects.forEach((value) => {
        this.addSubject(value);
      });
    }

    if (json.proof) {
      this.setProof(json.proof);
    }

    if (json.issuer) {
      this.setIssuer(json.issuer);
    }

    const status = (json.credentialStatus || json.status);
    if (status) {
      this.setStatus(status);
    }

    if (json.issuanceDate) {
      this.setIssuanceDate(json.issuanceDate);
    }

    if (json.expirationDate) {
      this.setExpirationDate(json.expirationDate);
    }

    Object.assign(this, json);
    return this;
  }

  static fromJSON(json) {
    const cert = new VerifiableCredential(json.id);
    const contexts = json['@context'];
    if (contexts) {
      cert.setContext(contexts);
    } else {
      throw new Error('No context found in JSON object, verifiable credentials must have a @context field.');
    }

    const types = json.type;
    if (types) {
      cert.type = [];
      if (types.length !== undefined) {
        types.forEach((typeVal) => {
          cert.addType(typeVal);
        });
      } else {
        cert.addType(types);
      }
    } else {
      throw new Error('No type found in JSON object, verifiable credentials must have a type field.');
    }

    return cert.setFromJSON(json);
  }
}


