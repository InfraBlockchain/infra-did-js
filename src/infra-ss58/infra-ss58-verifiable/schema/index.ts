import { canonicalize } from 'json-canonicalize';
import { validate } from 'jsonschema';
import axios from 'axios';
import { u8aToHex } from '@polkadot/util';
import { decodeAddress, encodeAddress, randomAsHex } from '@polkadot/util-crypto';
import { BLOB_QUALIFIER } from '../const'
import JSONSchema07 from './schema-draft-07';


export default class Schema {
    id: any;
    schema: any;
    private signature: any;

    constructor(networkId: string, id = undefined) {
        const ss58Id = encodeAddress(randomAsHex(32));
        this.id = id || `${BLOB_QUALIFIER}${networkId}:${ss58Id}`
    }
    static getHexIdFromBlobId(id: string) {
        if (id.startsWith(BLOB_QUALIFIER)) {
            const ss58Did = id.split('#')[0].split(':').pop();
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

    toJSON() {
        const { signature, ...rest } = this;
        return { ...rest, };
    }

    toBlob() {
        if (!this.schema) {
            throw new Error('Schema requires schema property to be serialized to blob');
        }
        return {
            id: Schema.getHexIdFromBlobId(this.id),
            blob: canonicalize(this.schema),
        };
    }

    async writeToChain(issuerDidAPI) {
        return await issuerDidAPI.blobModule.writeSchemaOnChainByBlob(this.toBlob())
    }
    static async validateSchema(json) {
        const jsonSchemaSpec = await this.getJSONSchemaSpec(json);
        return validate(json, jsonSchemaSpec, {
            throwError: true,
        });
    }

    static async get(id, didApi) {
        return await didApi.blobModule.getSchema(id);
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
