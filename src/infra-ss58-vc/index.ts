import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';
import { validate } from 'jsonschema';
import axios from 'axios';
import { u8aToHex } from '@polkadot/util';
import { blake2AsHex, decodeAddress, encodeAddress } from '@polkadot/util-crypto';
import CredentialIssuancePurpose from './CredentialIssuancePurpose';
import {
  EcdsaSecp256k1Signature2019, Sr25519Signature2020, Ed25519Signature2018,
  Bls12381BBSSignatureDock2022, Bls12381BBSSignatureProofDock2022
} from './crypto';
import cachedUris from './contexts';
import Schema from './schema';

export const RevRegType = 'CredentialStatusList2017';
export const DEFAULT_TYPE = 'VerifiableCredential';
export const DEFAULT_CONTEXT_URL = 'https://www.w3.org/2018/credentials';
export const DEFAULT_CONTEXT_V1_URL = `${DEFAULT_CONTEXT_URL}/v1`;
export const expandedStatusProperty = `${DEFAULT_CONTEXT_URL}#credentialStatus`;
export const expandedSubjectProperty = `${DEFAULT_CONTEXT_URL}#credentialSubject`;
export const expandedSchemaProperty = `${DEFAULT_CONTEXT_URL}#credentialSchema`;
export const credentialIDField = '@id';
export const credentialContextField = '@context';
export const credentialTypeField = '@type';
export const INFRA_DID_METHOD_AND_NETWORK = 'infra:space';
export const DIDQualifier = `did:${INFRA_DID_METHOD_AND_NETWORK}:`;
export const BlobQualifier = `blob:${INFRA_DID_METHOD_AND_NETWORK}:`;
export const RevRegQualifier = `rev-reg:${INFRA_DID_METHOD_AND_NETWORK}:`;
export const EcdsaSecp256k1VerKeyName = 'EcdsaSecp256k1VerificationKey2019';
export const Ed25519VerKeyName = 'Ed25519VerificationKey2018';
export const Sr25519VerKeyName = 'Sr25519VerificationKey2020';
export const Bls12381BBSDockVerKeyName = 'Bls12381G2VerificationKeyDock2022';


function parseEmbeddedDataURI(embedded) {
  const dataUri = embedded.replace(/\r?\n/g, '');
  const firstComma = dataUri.indexOf(',');
  if (firstComma === -1) {
    throw new Error('Malformed data URI');
  }

  const meta = dataUri.substring(5, firstComma).split(';');
  if (meta[0] !== 'application/json') {
    throw new Error(`Expected media type application/json but was ${meta[0]}`);
  }

  const isBase64 = meta.indexOf('base64') !== -1;
  if (isBase64) {
    throw new Error('Base64 embedded JSON is not yet supported');
  }
  const dataStr = decodeURIComponent(dataUri.substring(firstComma + 1));
  return JSON.parse(dataStr);
}

export function defaultDocumentLoader(resolver = null) {
  const loadDocument = async (documentUrl) => {
    let document;
    const uriString = documentUrl.toString();
    if (uriString.startsWith('data:')) {
      document = parseEmbeddedDataURI(uriString);
    } else if (resolver && uriString.startsWith('did:')) {
      document = await resolver.resolve(uriString);
    } else {
      const cacheKey = uriString.endsWith('/') ? uriString.substring(0, documentUrl.length - 1) : uriString;
      const cachedData = cachedUris.get(cacheKey);
      if (cachedData) {
        document = cachedData;
      } else {
        const { data: doc } = await axios.get(uriString);
        cachedUris.set(cacheKey, doc);
        document = doc;
      }
    }
    return { document, documentUrl, contextUrl: null, };
  }
  return loadDocument;
}

export function isHexWithByteSize(value) {
  if (isString(value)) {
    const match = value.match(/^0x([0-9a-f]+$)/i);
    if (match && match.length > 1) {
      return match[1].length === 64;
    }
  }
  return false;
}


export function hasRevocation(status) {
  const id = status[credentialIDField];
  if (status
    && (
      jsonld.getValues(status, credentialTypeField).includes(RevRegType)
      || jsonld.getValues(status, credentialTypeField).includes(`/${RevRegType}`)
    )
    && id.startsWith(RevRegQualifier)
    && isHexWithByteSize(id.slice(RevRegQualifier.length))) {
    return true;
  }

  return false;
}
export async function getCredentialStatuses(expanded) {
  const statusValues = jsonld.getValues(expanded, expandedStatusProperty);
  statusValues.forEach((status) => {
    if (!status[credentialIDField]) {
      throw new Error('"credentialStatus" must include an id.');
    }
    if (!status[credentialTypeField]) {
      throw new Error('"credentialStatus" must include a type.');
    }
  });

  return statusValues;
}
export async function checkRevocationStatus(credential, revocationApi) {
  if (!revocationApi) {
    throw new Error('No revocation API supplied');
  } else if (!revocationApi.dock) {
    throw new Error('Only Dock revocation support is present as of now.');
  } else {
    const statuses = await getCredentialStatuses(credential);
    const dockAPI = revocationApi.dock;
    const revId = blake2AsHex(credential[credentialIDField], 256);
    for (let i = 0; i < statuses.length; i++) {
      const status = statuses[i];
      if (!hasRevocation(status)) {
        return { verified: false, error: 'The credential status does not have the format required by infraDID' };
      }
      const regId = status[credentialIDField].slice(RevRegQualifier.length);
      const revocationStatus = await dockAPI.revocation.getIsRevoked(regId, revId);
      if (revocationStatus) {
        return { verified: false, error: 'Revocation check failed' };
      }
    }

    return { verified: true };
  }
}
export async function getAndValidateSchemaIfPresent(credential, schemaApi, context, documentLoader) {
  const schemaList = credential[expandedSchemaProperty];
  if (schemaList) {
    const schema = schemaList[0];
    if (credential[expandedSubjectProperty] && schema) {
      let schemaObj;
      const schemaUri = schema[credentialIDField];

      if (schemaUri.startsWith('blob:space')) {
        if (!schemaApi.dock) {
          throw new Error('Only infra space schemas are supported as of now.');
        }
        schemaObj = await Schema.get(schemaUri, schemaApi.dock);
      } else {
        const { document } = await documentLoader(schemaUri);
        schemaObj = document;
      }

      if (!schemaObj) {
        throw new Error(`Could not load schema URI: ${schemaUri}`);
      }

      await validateCredentialSchema(credential, schemaObj, context, documentLoader)
        .catch(e => { throw new Error(`Schema validation failed: ${e}`) })
    }
  }
}

export async function verifyCredential(credential, {
  resolver = null,
  compactProof = true,
  forceRevocationCheck = true,
  revocationApi = null,
  schemaApi = null,
  documentLoader = null,
  purpose = null,
  controller = null,
  suite = [],
  verifyDates = true,
} = {}) {

  if (documentLoader && resolver) {
    throw new Error('Passing resolver and documentLoader results in resolver being ignored, please re-factor.');
  }

  if (!credential) {
    throw new TypeError(
      'A "credential" property is required for verifying.',
    );
  }

  const docLoader = documentLoader || defaultDocumentLoader(resolver);

  checkCredential(credential);

  if (verifyDates && 'expirationDate' in credential) {
    const expirationDate = new Date(credential.expirationDate);
    const currentDate = new Date();
    if (currentDate > expirationDate) {
      const error = new Error('Credential has expired');
      return {
        verified: false,
        error,
        results: [{
          verified: false,
          expirationDate,
          error: {
            name: error.name,
            message: error.message,
          },
        }],
      };
    }
  }

  const expandedCredential = await expandJSONLD(credential, { documentLoader: docLoader, });
  if (schemaApi) {
    await getAndValidateSchemaIfPresent(expandedCredential, schemaApi, credential[credentialContextField], docLoader);
  }
  const result = await jsigs.verify(credential, {
    purpose: purpose || new CredentialIssuancePurpose({ controller }),
    suite: [new Ed25519Signature2018(), new EcdsaSecp256k1Signature2019(), new Sr25519Signature2020(), new Bls12381BBSSignatureDock2022(), new Bls12381BBSSignatureProofDock2022(), ...suite],
    documentLoader: docLoader,
    compactProof,
  });

  if (result.verified && !!expandedCredential[expandedStatusProperty] && (forceRevocationCheck || !!revocationApi)) {
    const revResult = await checkRevocationStatus(expandedCredential, revocationApi);
    if (!revResult.verified) {
      return revResult;
    }
  }
  return result;
}

export function getSuiteFromKeyDoc(keyDoc) {
  if (keyDoc.verificationMethod) {
    return keyDoc;
  }
  let Cls;

  switch (keyDoc.type) {
    case EcdsaSecp256k1VerKeyName:
      Cls = EcdsaSecp256k1Signature2019;
      break;
    case Ed25519VerKeyName:
      Cls = Ed25519Signature2018;
      break;
    case Sr25519VerKeyName:
      Cls = Sr25519Signature2020;
      break;
    case Bls12381BBSDockVerKeyName:
      Cls = Bls12381BBSSignatureDock2022;
      break;
    default:
      throw new Error(`Unknown key type ${keyDoc.type}.`);
  }
  return new Cls({
    ...keyDoc,
    verificationMethod: keyDoc.id,
  });
}

function getId(obj) {
  if (!obj) {
    return undefined;
  }
  if (typeof obj === 'string') {
    return obj;
  }
  return obj.id;
}
export function checkCredentialJSONLD(credential) {
  if (!jsonld.getValues(credential, 'type').includes('VerifiableCredential')) {
    throw new Error('"type" must include `VerifiableCredential`.');
  }
  if (jsonld.getValues(credential, 'issuanceDate').length > 1) {
    throw new Error('"issuanceDate" property can only have one value.');
  }
  if (jsonld.getValues(credential, 'issuer').length > 1) {
    throw new Error('"issuer" property can only have one value.');
  }
  jsonld.getValues(credential, 'evidence').forEach((evidence) => {
    const evidenceId = getId(evidence);
    if (evidenceId && !evidenceId.includes(':')) {
      throw new Error(`"evidence" id must be a URL: ${evidence}`);
    }
  });
}
export function checkCredentialRequired(credential) {
  if (credential['@context'][0] !== DEFAULT_CONTEXT_V1_URL) {
    throw new Error(`"${DEFAULT_CONTEXT_V1_URL}" needs to be first in the contexts array.`);
  }
  if (!credential.type) {
    throw new Error('"type" property is required.');
  }
  if (!credential.credentialSubject) {
    throw new Error('"credentialSubject" property is required.');
  }
  const issuer = getId(credential.issuer);
  if (!issuer) {
    throw new Error(`"issuer" must be an object with ID property or a string. Got: ${credential.issuer}`);
  } else if (!issuer.includes(':')) {
    throw new Error('"issuer" id must be in URL format.');
  }
  if (!credential.issuanceDate) {
    throw new Error('"issuanceDate" property is required.');
  } else {
    ensureValidDatetime(credential.issuanceDate);
  }
}
export function ensureValidDatetime(datetime) {
  const dateRegex = new RegExp('^(\\d{4})-(0[1-9]|1[0-2])-'
    + '(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):'
    + '([0-5][0-9]):([0-5][0-9]|60)'
    + '(\\.[0-9]+)?(Z|(\\+|-)([01][0-9]|2[0-3]):'
    + '([0-5][0-9]))$', 'i');
  if (!dateRegex.test(datetime)) {
    throw new Error(`${datetime} needs to be a valid datetime.`);
  }
  return true;
}
export function checkCredentialOptional(credential) {
  if ('credentialStatus' in credential) {
    if (!credential.credentialStatus.id) {
      throw new Error('"credentialStatus" must include an id.');
    }
    if (!credential.credentialStatus.type) {
      throw new Error('"credentialStatus" must include a type.');
    }
  }
  if ('expirationDate' in credential) {
    ensureValidDatetime(credential.expirationDate);
  }
}

export function checkCredential(credential) {
  checkCredentialRequired(credential);
  checkCredentialOptional(credential);
  checkCredentialJSONLD(credential);
}

export async function issueCredential(keyDoc, credential, compactProof = true, documentLoader = null, purpose = null, expansionMap = null, issuerObject = null, addSuiteContext = false) {
  const suite = getSuiteFromKeyDoc(keyDoc);
  if (!suite.verificationMethod) {
    throw new TypeError('"suite.verificationMethod" property is required.');
  }
  const issuerId = credential.issuer || keyDoc.controller;
  const cred = {
    ...credential,
    issuer: issuerObject ? {
      ...issuerObject,
      id: issuerId,
    } : issuerId,
  };

  checkCredential(cred);
  const sig = {
    purpose: purpose || new CredentialIssuancePurpose(),
    documentLoader: documentLoader || defaultDocumentLoader(),
    suite,
    compactProof,
    expansionMap,
    addSuiteContext,
  }
  return jsigs.sign(cred, sig);
}
export async function expandJSONLD(credential, options: any = {}) {
  if (options.documentLoader && options.resolver) {
    throw new Error('Passing resolver and documentLoader results in resolver being ignored, please re-factor.');
  }

  const expanded = await jsonld.expand(credential, {
    ...options,
    documentLoader: options.documentLoader || defaultDocumentLoader(options.resolver),
  });
  return expanded[0];
}

export async function validateCredentialSchema(credential, schema, context, documentLoader) {
  const requiresID = schema.required && schema.required.indexOf('id') > -1;
  const credentialSubject = credential[expandedSubjectProperty] || [];
  const subjects = credentialSubject.length ? credentialSubject : [credentialSubject];
  for (let i = 0; i < subjects.length; i++) {
    const subject = { ...subjects[i] };
    if (!requiresID) {
      delete subject[credentialIDField];
    }

    const compacted = await jsonld.compact(subject, context, { documentLoader: documentLoader || defaultDocumentLoader() }); // eslint-disable-line
    delete compacted[credentialContextField];

    if (Object.keys(compacted).length === 0) {
      throw new Error('Compacted subject is empty, likely invalid');
    }

    validate(compacted, schema.schema || schema, { throwError: true });
  }
  return true;
}
export function getUniqueElementsFromArray(a, filterCallback) {
  const seen = new Set();
  return a.filter((item) => {
    const k = filterCallback(item);
    return seen.has(k) ? false : seen.add(k);
  });
}
export function isObject(value) {
  return value && typeof value === 'object' && value.constructor === Object;
}
export function isString(value) {
  return typeof value === 'string' || value instanceof String;
}

export function ensureString(value) {
  if (!isString(value)) {
    throw new Error(`${value} needs to be a string.`);
  }
}

export function ensureURI(uri) {
  ensureString(uri);
  const pattern = new RegExp('^\\w+:\\/?\\/?[^\\s]+$');
  if (!pattern.test(uri)) {
    throw new Error(`${uri} needs to be a valid URI.`);
  }
}

export default class VerifiableCredential {
  private context: any[];
  private type: any[];
  private credentialSubject: any[];
  private issuer: any;
  private proof: any;
  private credentialSchema: { id: any; type: any; };
  private id: any;
  private status: any;
  private issuanceDate: any;
  private expirationDate: any;

  constructor(id) {
    if (id) {
      this.setId(id);
    }
    this.context = [DEFAULT_CONTEXT_V1_URL];
    this.type = [DEFAULT_TYPE];
    this.credentialSubject = [];
    this.setIssuanceDate(new Date().toISOString());
  }

  setId(id) {
    ensureURI(id);
    this.id = id;
    return this;
  }
  setIssuer(issuer) {
    this.issuer = issuer;
    return this;
  }

  setProof(proof) {
    this.proof = proof;
    return this;
  }

  setSchema(id, type) {
    ensureURI(id);
    this.credentialSchema = {
      id, type,
    };
  }

  async validateSchema(schema) {
    if (!this.credentialSubject) {
      throw new Error('No credential subject defined');
    }

    const expanded = await expandJSONLD(this.toJSON());
    return validateCredentialSchema(expanded, schema, this.context, undefined);
  }

  setContext(context) {
    if (!isObject(context) && !Array.isArray(context)) {
      ensureURI(context);
    }
    this.context = context;
    return this;
  }

  addContext(context) {
    if (!isObject(context)) {
      ensureURI(context);
    }
    this.context = getUniqueElementsFromArray([...this.context, context], JSON.stringify);
    return this;
  }

  addType(type) {
    ensureString(type);
    this.type = [...new Set([...this.type, type])];
    return this;
  }

  addSubject(subject) {
    if (!this.credentialSubject || this.credentialSubject.length === 0) {
      this.credentialSubject = [subject];
    }
    const subjects = this.credentialSubject.length ? this.credentialSubject : [this.credentialSubject];
    this.credentialSubject = getUniqueElementsFromArray([...subjects, subject], JSON.stringify);
    return this;
  }

  setSubject(subject) {
    if (!isObject(subject) && !Array.isArray(subject)) {
      throw new Error('credentialSubject must be either an object or array');
    }
    this.credentialSubject = subject;
    return this;
  }

  ensureObject(value) {
    if (!isObject(value)) {
      throw new Error(`${value} needs to be an object.`);
    }
  }
  ensureObjectWithKey(value, key, name) {
    this.ensureObject(value);
    if (!(key in value)) {
      throw new Error(`"${name}" must include the '${key}' property.`);
    }
  }

  setStatus(status) {
    this.ensureObjectWithKey(status, 'id', 'credentialStatus');
    if (!status.type) {
      throw new Error('"credentialStatus" must include a type.');
    }
    this.status = status;
    return this;
  }

  setIssuanceDate(issuanceDate) {
    ensureValidDatetime(issuanceDate);
    this.issuanceDate = issuanceDate;
    return this;
  }

  setExpirationDate(expirationDate) {
    ensureValidDatetime(expirationDate);
    this.expirationDate = expirationDate;
    return this;
  }

  toJSON() {
    const { context, status, ...rest } = this;
    const obj = {
      '@context': this.context,
      credentialStatus: this.status,
      ...rest
    }
    return JSON.parse(JSON.stringify(obj));
  }

  async sign(keyDoc, compactProof = true, issuerObject = null, addSuiteContext = false) {
    const signedVC = await issueCredential(
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

  async verify({
    resolver = null, compactProof = true, forceRevocationCheck = true, revocationApi = null, schemaApi = null, suite = [],
  } = {}) {
    if (!this.proof) {
      throw new Error('The current Verifiable Credential has no proof.');
    }

    return verifyCredential(this.toJSON(), {
      resolver,
      compactProof,
      forceRevocationCheck,
      revocationApi,
      schemaApi,
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

