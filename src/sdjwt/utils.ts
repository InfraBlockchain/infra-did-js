import crypto, { BinaryLike } from 'crypto'

import { decode, encode } from "./base64url";
import { FORMAT_SEPARATOR } from './constants';
import { CompactSDJWT, Disclosure, DisclosureClaim, Hasher, SaltGenerator, SDJWT, UnverifiedJWT } from "./types";

export function generateSalt(length: number): string {
    let salt = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
        salt += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return salt;
}

export function hasher(data: BinaryLike): string {
    const digest = crypto.createHash('sha256').update(data).digest();
    const hash = Buffer.from(digest).toString('base64url');
    return hash;
};

export function base64encode(input: string | Uint8Array): string {
    return encode(input);
}

export function base64decode(input: string): string {
    return decode(input).toString();
}

/**
 * Helpers for packSDJWT
 */
export function createDisclosure(
    claim: DisclosureClaim,
    hasher: Hasher,
    options?: {
        generateSalt?: SaltGenerator;
    },
): {
    hash: string;
    disclosure: string;
} {
    let disclosureArray;
    const saltGenerator = options?.generateSalt ? options.generateSalt : generateSalt;
    const salt = saltGenerator(16);
    if (claim.key) {
        disclosureArray = [salt, claim.key, claim.value];
    } else {
        disclosureArray = [salt, claim.value];
    }

    const disclosure = base64encode(JSON.stringify(disclosureArray));
    const hash = hasher(disclosure);
    return {
        hash,
        disclosure,
    };
};

export function createDecoy(count: number, hasher: Hasher, saltGenerator: SaltGenerator = generateSalt): string[] {
    if (count < 0) {
        throw new Error('decoy count must not be less than zero');
    }

    const decoys = [];

    for (let i = 0; i < count; i++) {
        const salt = saltGenerator(16);
        const decoy = hasher(salt);
        decoys.push(decoy);
    }

    return decoys;
};


export function combineSDJWT(jwt: string, disclosures: string[], kbjwt?: string): CompactSDJWT {
    let combined: CompactSDJWT = jwt;

    if (disclosures.length > 0) {
        combined += FORMAT_SEPARATOR + disclosures.join(FORMAT_SEPARATOR);
    }

    combined += FORMAT_SEPARATOR;

    if (kbjwt) {
        combined += kbjwt;
    }

    return combined;
};

export function decodeSDJWT(sdJWT: string): SDJWT {
    const s = sdJWT.split(FORMAT_SEPARATOR);

    // disclosures may be empty
    // but the separator before the key binding jwt must exist
    if (s.length < 2) {
        throw new Error('Not a valid SD-JWT');
    }
    const { header, payload: unverifiedInputSdJwt } = decodeJWT(s.shift() || '');
    const keyBindingJWT = s.pop();
    const disclosures = decodeDisclosure(s);

    return {
        header,
        unverifiedInputSdJwt,
        disclosures,
        keyBindingJWT,
    };
};

/**
 * Helpers for UnpackSDJWT
 */
export function decodeDisclosure(disclosures: string[]): Array<Disclosure> {
    return disclosures.map((d) => {
        const decoded = JSON.parse(base64decode(d));

        let key;
        let value;

        // if disclosure is a value in an array
        // [<SALT>, <VALUE>]
        if (decoded.length == 2) {
            value = decoded[1];
        }
        // if disclosure is a value in an object
        // [<SALT>, <KEY>, <VALUE>]
        if (decoded.length == 3) {
            key = decoded[1];
            value = decoded[2];
        }

        return {
            disclosure: d,
            key,
            value,
        };
    });
};

// no verification
export function decodeJWT(input: string): UnverifiedJWT {
    if (typeof input !== 'string') {
        throw new Error('Invalid input');
    }

    const { 0: header, 1: payload, 2: signature, length } = input.split('.');
    if (length !== 3) {
        throw new Error('Invalid JWT as input');
    }

    return {
        header: JSON.parse(base64decode(header)),
        payload: JSON.parse(base64decode(payload)),
        signature,
    };
}

