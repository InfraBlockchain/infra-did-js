import jsonldjs from 'jsonld';
import jsigs from 'jsonld-signatures';
import { validate } from 'jsonschema';
import axios from 'axios';
import b58 from 'bs58';
import { blake2AsHex, } from '@polkadot/util-crypto';
import { BBSPlusPublicKeyG2 } from '@docknetwork/crypto-wasm-ts';
import { Presentation } from '@docknetwork/crypto-wasm-ts/lib/anonymous-credentials/presentation';
import {
    EcdsaSecp256k1Signature2019, Sr25519Signature2020, Ed25519Signature2018,
    Bls12381BBSSignatureDock2022, Bls12381BBSSignatureProofDock2022, Bls12381BBSDockVerKeyName
} from './crypto';
import cachedUris from './contexts';
import {
    REV_REG_TYPE, DEFAULT_CONTEXT_V1_URL,
    EXPANDED_STATUS_PROPERTY, EXPANDED_SUBJECT_PROPERTY, EXPANDED_SCHEMA_PROPERTY,
    CREDENTIAL_ID, CREDENTIAL_CONTEXT, CREDENTIAL_TYPE,
    REV_REG_QUALIFIER,
    BLOB_QUALIFIER,
} from './const'
import { CRYPTO_INFO } from '../ss58.interface';

const jsonld: any = jsonldjs;
const { AuthenticationProofPurpose, AssertionProofPurpose } = jsigs.purposes;

export function defaultDocumentLoader(resolver: any = null) {
    const loadDocument = async (documentUrl) => {
        let document;
        const uriString = documentUrl.toString();
        if (uriString.startsWith('data:')) {
            const dataUri = uriString.replace(/\r?\n/g, '');
            const firstComma = dataUri.indexOf(',');
            if (firstComma === -1) {
                throw new Error('Malformed data URI');
            }
            const meta = dataUri.substring(5, firstComma).split(';');
            if (meta[0] !== 'application/json') {
                throw new Error(`Expected media type application/json but was ${meta[0]}`);
            }
            if (meta.indexOf('base64') !== -1) {
                throw new Error('Base64 embedded JSON is not yet supported');
            }
            document = JSON.parse(decodeURIComponent(dataUri.substring(firstComma + 1)));
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

export class VerifiableHelper {
    constructor() {}
    private isHexWithByteSize(value) {
        if (this.isString(value)) {
            const match = value.match(/^0x([0-9a-f]+$)/i);
            if (match && match.length > 1) {
                return match[1].length === 64;
            }
        }
        return false;
    }

    private hasRevocation(status) {
        const id = status[CREDENTIAL_ID];
        const ss58DID = id.split('#')[0].split(':').pop();

        if (status
            && (
                jsonld.getValues(status, CREDENTIAL_TYPE).includes(REV_REG_TYPE)
                || jsonld.getValues(status, CREDENTIAL_TYPE).includes(`/${REV_REG_TYPE}`)
            )
            && id.startsWith(REV_REG_QUALIFIER)
            && this.isHexWithByteSize(ss58DID)) {
            return true;
        }

        return false;
    }

    private getId(obj) {
        if (!obj) {
            return undefined;
        }
        if (typeof obj === 'string') {
            return obj;
        }
        return obj.id;
    }
    private checkCredentialJSONLD(credential) {
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
            const evidenceId = this.getId(evidence);
            if (evidenceId && !evidenceId.includes(':')) {
                throw new Error(`"evidence" id must be a URL: ${evidence}`);
            }
        });
    }
    private checkCredentialRequired(credential) {
        if (credential['@context'][0] !== DEFAULT_CONTEXT_V1_URL) {
            throw new Error(`"${DEFAULT_CONTEXT_V1_URL}" needs to be first in the contexts array.`);
        }
        if (!credential.type) {
            throw new Error('"type" property is required.');
        }
        if (!credential.credentialSubject) {
            throw new Error('"credentialSubject" property is required.');
        }
        const issuer = this.getId(credential.issuer);
        if (!issuer) {
            throw new Error(`"issuer" must be an object with ID property or a string. Got: ${credential.issuer}`);
        } else if (!issuer.includes(':')) {
            throw new Error('"issuer" id must be in URL format.');
        }
        if (!credential.issuanceDate) {
            throw new Error('"issuanceDate" property is required.');
        } else {
            this.ensureValidDatetime(credential.issuanceDate);
        }
    }

    private checkCredentialOptional(credential) {
        if ('credentialStatus' in credential) {
            if (!credential.credentialStatus.id) {
                throw new Error('"credentialStatus" must include an id.');
            }
            if (!credential.credentialStatus.type) {
                throw new Error('"credentialStatus" must include a type.');
            }
        }
        if ('expirationDate' in credential) {
            this.ensureValidDatetime(credential.expirationDate);
        }
    }

    private checkCredential(credential) {
        this.checkCredentialRequired(credential);
        this.checkCredentialOptional(credential);
        this.checkCredentialJSONLD(credential);
    }

    private checkPresentation(presentation) {
        // Normalize to an array to allow the common case of context being a string
        const context = Array.isArray(presentation['@context'])
            ? presentation['@context'] : [presentation['@context']];

        // Ensure first context is 'https://www.w3.org/2018/credentials/v1'
        if (context[0] !== DEFAULT_CONTEXT_V1_URL) {
            throw new Error(
                `"${DEFAULT_CONTEXT_V1_URL}" needs to be first in the `
                + 'list of contexts.',
            );
        }

        // Ensure VerifiablePresentation exists in types
        const types = jsonld.getValues(presentation, 'type');
        if (!types.includes('VerifiablePresentation')) {
            throw new Error('"type" must include "VerifiablePresentation".');
        }
    }

    private async getCredentialStatuses(expanded) {
        const statusValues = jsonld.getValues(expanded, EXPANDED_STATUS_PROPERTY);
        statusValues.forEach((status) => {
            if (!status[CREDENTIAL_ID]) {
                throw new Error('"credentialStatus" must include an id.');
            }
            if (!status[CREDENTIAL_TYPE]) {
                throw new Error('"credentialStatus" must include a type.');
            }
        });

        return statusValues;
    }

    private async getAndValidateSchemaIfPresent(credential, blobModule, context, documentLoader) {
        const schemaList = credential[EXPANDED_SCHEMA_PROPERTY];
        if (schemaList) {
            const schema = schemaList[0];
            if (credential[EXPANDED_SUBJECT_PROPERTY] && schema) {
                let schemaObj;
                const schemaUri = schema[CREDENTIAL_ID];
                if (schemaUri.startsWith(BLOB_QUALIFIER)) {
                    schemaObj = await blobModule.getSchema(schemaUri);
                } else {
                    const { document } = await documentLoader(schemaUri);
                    schemaObj = document;
                }

                if (!schemaObj) {
                    throw new Error(`Could not load schema URI: ${schemaUri}`);
                }

                await this.validateCredentialSchema(credential, schemaObj, context, documentLoader)
                    .catch(e => { throw new Error(`Schema validation failed: ${e}`) })
            }
        }
    }

    protected ensureValidDatetime(datetime) {
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
    protected isObject(value) {
        return value && typeof value === 'object' && value.constructor === Object;
    }
    protected isString(value) {
        return typeof value === 'string' || value instanceof String;
    }


    protected ensureObjectWithKey(value, key, name) {
        if (!this.isObject(value)) {
            throw new Error(`${value} needs to be an object.`);
        }
        if (!(key in value)) {
            throw new Error(`"${name}" must include the '${key}' property.`);
        }
    }

    protected ensureString(value) {
        if (!this.isString(value)) {
            throw new Error(`${value} needs to be a string.`);
        }
    }

    protected ensureURI(uri) {
        this.ensureString(uri);
        const pattern = new RegExp('^\\w+:\\/?\\/?[^\\s]+$');
        if (!pattern.test(uri)) {
            throw new Error(`${uri} needs to be a valid URI.`);
        }
    }

    protected getUniqueElementsFromArray(a, filterCallback) {
        const seen = new Set();
        return a.filter((item) => {
            const k = filterCallback(item);
            return seen.has(k) ? false : seen.add(k);
        });
    }

    protected getSuiteFromKeyDoc(keyDoc) {
        if (keyDoc.verificationMethod) {
            return keyDoc;
        }
        let Cls;
        switch (keyDoc.type) {
            case CRYPTO_INFO.Secp256k1.KEY_TYPE:
                Cls = EcdsaSecp256k1Signature2019;
                break;
            case CRYPTO_INFO.ED25519.KEY_TYPE:
                Cls = Ed25519Signature2018;
                break;
            case CRYPTO_INFO.SR25519.KEY_TYPE:
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

    protected async checkRevocationStatus(credential, revocationModule) {
        if (!revocationModule) {
            throw new Error('No revocation API supplied');
        } else {
            const statuses = await this.getCredentialStatuses(credential);
            const revId = blake2AsHex(credential[CREDENTIAL_ID], 256);
            for (let i = 0; i < statuses.length; i++) {
                const status = statuses[i];
                if (!this.hasRevocation(status)) {
                    return { verified: false, error: 'The credential status does not have the format required by infraDID' };
                }
                const regId = status[CREDENTIAL_ID].split('#')[0].split(':').pop();
                const revocationStatus = await revocationModule.getIsRevoked(regId, revId);
                if (revocationStatus) {
                    return { verified: false, error: 'Revocation check failed' };
                }
            }

            return { verified: true };
        }
    }

    protected async verifyCredential(credential, {
        resolver = null,
        compactProof = true,
        forceRevocationCheck = true,
        revocationModule = null,
        blobModule = null,
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

        this.checkCredential(credential);

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

        const expandedCredential = await this.expandJSONLD(credential, { documentLoader: docLoader, });
        if (blobModule) {
            await this.getAndValidateSchemaIfPresent(expandedCredential, blobModule, credential[CREDENTIAL_CONTEXT], docLoader);
        }
        const result = await jsigs.verify(credential, {
            purpose: purpose || new CredentialIssuancePurpose(this.expandJSONLD, { controller }),
            suite: [new Ed25519Signature2018(), new EcdsaSecp256k1Signature2019(), new Sr25519Signature2020(), new Bls12381BBSSignatureDock2022(), new Bls12381BBSSignatureProofDock2022(), ...suite],
            documentLoader: docLoader,
            compactProof,
        });

        if (result.verified && !!expandedCredential[EXPANDED_STATUS_PROPERTY] && (forceRevocationCheck || !!revocationModule)) {
            const revResult = await this.checkRevocationStatus(expandedCredential, revocationModule);
            if (!revResult.verified) {
                return revResult;
            }
        }
        return result;
    }

    protected async issueCredential(keyDoc, credential, compactProof = true, documentLoader = null, purpose = null, expansionMap = null, issuerObject: any = null, addSuiteContext = false) {
        const suite = this.getSuiteFromKeyDoc(keyDoc);
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

        this.checkCredential(cred);
        const sig = {
            purpose: purpose || new CredentialIssuancePurpose(this.expandJSONLD),
            documentLoader: documentLoader || defaultDocumentLoader(),
            suite,
            compactProof,
            expansionMap,
            addSuiteContext,
        }
        return jsigs.sign(cred, sig);
    }
    private async verifyBBSPlusPresentation(presentation, options: any = {}) {
        const documentLoader = options.documentLoader || defaultDocumentLoader(options.resolver);

        const keyDocuments = await Promise.all(presentation.spec.credentials.map((c, idx) => {
            const { proof } = c.revealedAttributes;
            if (!proof) {
                throw new Error(`Presentation credential does not reveal its proof for index ${idx}`);
            }
            return Bls12381BBSSignatureDock2022.getVerificationMethod({ proof, documentLoader });
        }));

        const recreatedPres = Presentation.fromJSON(presentation);
        const pks = keyDocuments.map((keyDocument) => {
            const pkRaw = b58.decode(keyDocument.publicKeyBase58);
            return new BBSPlusPublicKeyG2(pkRaw);
        });

        return recreatedPres.verify(pks);
    }
    private async verifyPresentationCredentials(presentation, options = {}) {
        let verified = true;
        let credentialResults: any = [];

        // Get presentation credentials
        const credentials = jsonld.getValues(presentation, 'verifiableCredential');
        if (credentials.length > 0) {
            // Verify all credentials in list
            credentialResults = await Promise.all(credentials.map((credential) => this.verifyCredential(credential, { ...options })));

            // Assign credentialId property to all credential results
            for (const [i, credentialResult] of credentialResults.entries()) {
                credentialResult.credentialId = credentials[i].id;
            }

            // Check all credentials passed verification
            const allCredentialsVerified = credentialResults.every((r) => r.verified);
            if (!allCredentialsVerified) {
                verified = false;
            }
        }

        return {
            verified,
            credentialResults,
        };
    }
    protected async verifyPresentation(presentation, options: any = {}) {
        if (options.documentLoader && options.resolver) {
            throw new Error('Passing resolver and documentLoader results in resolver being ignored, please re-factor.');
        }
        if (!presentation) {
            throw new TypeError('"presentation" property is required');
        }
        if (typeof presentation.version === 'string' && typeof presentation.proof === 'string' &&
            typeof presentation.spec !== 'undefined' && typeof presentation.spec.credentials !== 'undefined') {
            return this.verifyBBSPlusPresentation(presentation, options);
        }
        this.checkPresentation(presentation);
        const {
            challenge,
            domain,
            resolver,
            unsignedPresentation = false,
            presentationPurpose,
            controller,
            suite = [],
        } = options;
        const verificationOptions = {
            documentLoader: options.documentLoader || defaultDocumentLoader(resolver),
            ...options,
            resolver: null,
            suite: [new Ed25519Signature2018(), new EcdsaSecp256k1Signature2019(), new Sr25519Signature2020(), ...suite],
        };

        // TODO: verify proof then credentials
        const { verified, credentialResults } = await this.verifyPresentationCredentials(presentation, verificationOptions);
        try {
            if (unsignedPresentation) {
                return { verified, results: [presentation], credentialResults };
            }
            if (!verified) {
                return { verified, results: [presentation], credentialResults };
            }
            if (!presentationPurpose && !challenge) {
                throw new Error(
                    'A "challenge" param is required for AuthenticationProofPurpose.',
                );
            }
            const purpose = presentationPurpose || new AuthenticationProofPurpose({ controller, domain, challenge });
            const presentationResult = await jsigs.verify(
                presentation, { purpose, ...verificationOptions },
            );
            return {
                presentationResult,
                credentialResults,
                verified: verified && presentationResult.verified,
                error: presentationResult.error,
            };
        } catch (error) {
            return { verified: false, results: [{ verified: false, error }], error };
        }
    }

    protected async signPresentation(presentation, keyDoc, challenge, domain, resolver: any = null, compactProof = true, presentationPurpose = null) {
        const suite = this.getSuiteFromKeyDoc(keyDoc);
        const purpose = presentationPurpose || new AuthenticationProofPurpose({
            domain,
            challenge,
        });

        const documentLoader = defaultDocumentLoader(resolver);
        return jsigs.sign(presentation, {
            purpose, documentLoader, domain, challenge, compactProof, suite,
        });
    }

    protected async expandJSONLD(credential: any, options: any = {}) {
        if (options.documentLoader && options.resolver) {
            throw new Error('Passing resolver and documentLoader results in resolver being ignored, please re-factor.');
        }
        const expanded = await jsonld.expand(credential, {
            ...options,
            documentLoader: options.documentLoader || defaultDocumentLoader(options.resolver),
        });
        return expanded[0];
    }

    protected async validateCredentialSchema(credential, schema, context, documentLoader) {
        const requiresID = schema.required && schema.required.indexOf('id') > -1;
        const credentialSubject = credential[EXPANDED_SUBJECT_PROPERTY] || [];
        const subjects = credentialSubject.length ? credentialSubject : [credentialSubject];
        documentLoader ??= defaultDocumentLoader()
        for (let i = 0; i < subjects.length; i++) {
            const subject = { ...subjects[i] };
            if (!requiresID) {
                delete subject[CREDENTIAL_ID];
            }

            const compacted = await jsonld.compact(subject, context, { documentLoader });
            delete compacted[CREDENTIAL_CONTEXT];

            if (Object.keys(compacted).length === 0) {
                throw new Error('Compacted subject is empty, likely invalid');
            }

            validate(compacted, schema.schema || schema, { throwError: true });
        }
        return true;
    }


}

class CredentialIssuancePurpose extends AssertionProofPurpose {

    constructor(private expandJSONLD, { controller, date = undefined, maxTimestampDelta = undefined }: any = {}) {
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

            const expandedDoc = await this.expandJSONLD(document, {
                documentLoader,
            });

            const issuer = jsonld.getValues(expandedDoc,
                'https://www.w3.org/2018/credentials#issuer',);

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
