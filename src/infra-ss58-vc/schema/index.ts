import { canonicalize } from 'json-canonicalize';
import { validate } from 'jsonschema';
import axios from 'axios';
import { u8aToHex } from '@polkadot/util';
import { decodeAddress, encodeAddress, randomAsHex } from '@polkadot/util-crypto';
import { BlobQualifier, DIDQualifier, isString } from '../'
import JSONSchema07 from './schema-draft-07';
import InfraSS58DID, { CRYPTO_INFO } from '../../infra-ss58';


export class Signature {
    value: string;
    sigType: any;
    constructor(message, signingPair, sigType) {
        this.fromPolkadotJSKeyringPair(message, signingPair, sigType);
    }
    fromHex(value, sigType) {
        this.validateByteSize(value);

        // @ts-ignore
        const sig = Object.create(this.prototype);
        sig.value = value;
        sig.sigType = sigType;
        return sig;
    }

    validateByteSize(value) {
        if (isString(value)) {
            const match = value.match(/^0x([0-9a-f]+$)/i);
            if (match && match.length > 1 && match[1].length === (64)) {
                return true;
            }
        }
        throw new Error(`Signature must be ${64} bytes`);
    }

    fromPolkadotJSKeyringPair(message, signingPair, sigType) {
        this.value = u8aToHex(signingPair.sign(message));
        this.sigType = sigType;
    }

    toJSON() {
        return { [this.sigType]: this.value };
    }
}
export function getHexIdentifier(id, qualifier) {
    if (id.startsWith(qualifier)) {
        const ss58Did = id.slice(qualifier.length);
        try {
            const hex = u8aToHex(decodeAddress(ss58Did));
            if (hex.length !== (66)) {
                throw new Error('Unexpected byte size');
            }
            return hex;
        } catch (e) {
            throw new Error(`Invalid SS58 ID ${id}. ${e}`);
        }
    } else {
        return id;
    }
}
export function getHexIdentifierFromBlobID(id) {
    return getHexIdentifier(id, 'blob:infra:space:');
}


export default class Schema {
    private id: any;
    private schema: any;
    private signature: any;

    constructor(id = undefined) {
        const ss58Id = encodeAddress(randomAsHex(32));
        this.id = id || `${BlobQualifier}${ss58Id}`
    }

    static fromJSON(json) {
        const { id, schema, } = json;
        const schemaObj = new Schema(id);
        if (schema) {
            schemaObj.schema = schema;
        }
        return schemaObj;
    }

    async setJSONSchema(json) {
        await Schema.validateSchema(json);
        this.schema = json;
        return this;
    }

    sign(pair, blobModule) {
        const serializedBlob = blobModule.getSerializedBlob(this.toBlob());
        if (pair.type === CRYPTO_INFO.ED25519) {
            this.signature = new Signature(serializedBlob, pair, CRYPTO_INFO.ED25519.SIG_TYPE);
        } else if (pair.type === CRYPTO_INFO.SR25519) {
            this.signature = new Signature(serializedBlob, pair, CRYPTO_INFO.SR25519.SIG_TYPE);
        } else throw new Error("not supported pair type");
        return this;
    }

    toJSON() {
        const { signature, ...rest } = this;
        return { ...rest, };
    }

    toBlob() {
        if (!this.schema) {
            throw new Error('Schema requires schema property to be serialized to blob');
        }
        return {
            id: getHexIdentifierFromBlobID(this.id),
            blob: canonicalize(this.schema),
        };
    }

    async writeToChain(issuerDidAPI: InfraSS58DID) {

        return await issuerDidAPI.writeSchemaOnChain(this.toBlob())
        // return dock.blob.new(this.toBlob(), signerDid, keyPair, keyId, arg, waitForFinalization, params);
    }
    static async validateSchema(json) {
        const jsonSchemaSpec = await this.getJSONSchemaSpec(json);
        return validate(json, jsonSchemaSpec, {
            throwError: true,
        });
    }

    static async get(id, dockApi) {
        const hexId = getHexIdentifierFromBlobID(id);
        const chainBlob = await dockApi.blob.get(hexId);
        const chainValue = chainBlob[1];

        if (typeof chainValue === 'object' && !(chainValue instanceof Uint8Array)) {
            const ss58Id = encodeAddress(chainBlob[0]);
            const author = `${DIDQualifier}${ss58Id}`;
            return { ...chainValue, id, author };
        }
        throw new Error('Incorrect schema format');
    }

    static async getJSONSchemaSpec(json) {
        const schemaKey = '$schema';
        const schemaUrl = json[schemaKey];
        if (schemaUrl) {
            // The URL might be 'http://json-schema.org/draft-07/schema' or 'http://json-schema.org/draft-07/schema#'
            // In that case, the schema is already stored in the SDK as this is the latest JSON schema spec
            if (schemaUrl === 'http://json-schema.org/draft-07/schema' || schemaUrl === 'http://json-schema.org/draft-07/schema#') {
                // Return stored JSON schema
                return JSONSchema07;
            }
            // Fetch the URI and expect a JSON response
            const { data: doc } = await axios.get(schemaUrl);
            if (typeof doc === 'object') {
                return doc;
            }
            // If MIME type did not indicate JSON, try to parse the response as JSON
            try {
                return JSON.parse(doc);
            } catch (e) {
                throw new Error('Cannot parse response as JSON');
            }
        } else {
            throw new Error(`${schemaKey} not found in the given JSON`);
        }
    }
}
