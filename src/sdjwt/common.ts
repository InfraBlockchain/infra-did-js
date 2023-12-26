import { DEFAULT_SD_HASH_ALG, SD_DECOY_COUNT, SD_DIGEST, SD_HASH_ALG, SD_LIST_PREFIX } from "./constants";
import { Disclosure, DisclosureFrame, GetHasher, Hasher, SaltGenerator, SdDigestHashmap, SDJWTPayload } from "./types";
import { createDecoy, createDisclosure } from "./utils";

export async function packSDJWT(
    claims: object | Array<any>,
    disclosureFrame: DisclosureFrame,
    hasher: Hasher,
    options?: {
        generateSalt?: SaltGenerator;
    },
) {
    const sd = disclosureFrame[SD_DIGEST];

    let packedClaims;
    let disclosures: any[] = [];

    if (claims instanceof Array) {
        packedClaims = [];
        const recursivelyPackedClaims = {};

        for (const key in disclosureFrame) {
            if (key !== SD_DIGEST && key !== SD_DECOY_COUNT) {
                const idx = parseInt(key);
                const packed = await packSDJWT(claims[idx], disclosureFrame[idx] as DisclosureFrame, hasher, options);
                recursivelyPackedClaims[idx] = packed.claims;
                disclosures = disclosures.concat(packed.disclosures);
            }
        }

        for (let i = 0; i < (claims as Array<any>).length; i++) {
            const claim = recursivelyPackedClaims[i] ? recursivelyPackedClaims[i] : claims[i];
            if (sd?.includes(i)) {
                const { hash, disclosure } = await createDisclosure({ value: claim }, hasher, options);
                packedClaims.push({ '...': hash });
                disclosures.push(disclosure);
            } else {
                packedClaims.push(claim);
            }
        }

        const decoys = createDecoy(disclosureFrame[SD_DECOY_COUNT], hasher, options?.generateSalt);
        decoys.forEach((decoy) => {
            packedClaims.push({ '...': decoy });
        });
    } else {
        packedClaims = {};
        const recursivelyPackedClaims = {};
        for (const key in disclosureFrame) {
            if (key !== SD_DIGEST && key !== SD_DECOY_COUNT) {
                const packed = await packSDJWT(claims[key], disclosureFrame[key] as DisclosureFrame, hasher, options);
                recursivelyPackedClaims[key] = packed.claims;
                disclosures = disclosures.concat(packed.disclosures);
            }
        }

        const _sd: string[] = [];

        for (const key in claims) {
            const claim = recursivelyPackedClaims[key] ? recursivelyPackedClaims[key] : claims[key];
            if (sd?.includes(key)) {
                const { hash, disclosure } = await createDisclosure({ key, value: claim }, hasher, options);
                _sd.push(hash);
                disclosures.push(disclosure);
            } else {
                packedClaims[key] = claim;
            }
        }

        const decoys = createDecoy(disclosureFrame[SD_DECOY_COUNT], hasher, options?.generateSalt);
        decoys.forEach((decoy) => {
            _sd.push(decoy);
        });

        if (_sd.length > 0) {
            packedClaims[SD_DIGEST] = _sd.sort();
        }
    }
    return { claims: packedClaims, disclosures };
}

/**
 * Replaces _sd digests present in the SD-JWT with disclosed claims
 *
 * @param sdJWT SD-JWT
 * @param disclosures Array of Disclosure
 * @returns sd-jwt with all disclosed claims
 */
export async function unpackSDJWT(
    sdjwt: SDJWTPayload,
    disclosures: Array<Disclosure>,
    getHasher: GetHasher,
): Promise<SDJWTPayload> {
    const hashAlg = (sdjwt[SD_HASH_ALG] as string) || DEFAULT_SD_HASH_ALG;
    const hasher = await getHasher(hashAlg);
    const map = createHashMapping(disclosures, hasher);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { _sd_alg, ...payload } = sdjwt;
    return unpack({ obj: payload, map });
};

export function createHashMapping(disclosures: Disclosure[], hasher: Hasher): SdDigestHashmap {
    const map = {};
    disclosures.forEach((d) => {
        const digest = hasher(d.disclosure);
        map[digest] = d;
    });
    return map;
};

/**
 * Iterates through an object
 * recursively unpack any child object or array
 * inserts claims if disclosed
 * removes any undisclosed claims
 */
export function unpack({ obj, map }) {
    if (obj instanceof Object) {
        if (obj instanceof Array) {
            return unpackArray({ arr: obj, map });
        }

        for (const key in obj) {
            // if obj property value is an object
            // recursively unpack
            if (key !== SD_DIGEST && key !== SD_LIST_PREFIX && obj[key] instanceof Object) {
                obj[key] = unpack({ obj: obj[key], map });
            }
        }

        const { _sd, ...payload } = obj;
        const claims = {};
        if (_sd) {
            _sd.forEach((hash) => {
                const disclosed = map[hash];
                if (disclosed) {
                    claims[disclosed.key] = unpack({ obj: disclosed.value, map });
                }
            });
        }

        return Object.assign(payload, claims);
    }
    return obj;
};

/**
* Iterates through an array
* inserts claim if disclosed
* removes any undisclosed claims
*/
export function unpackArray({ arr, map }) {
    const unpackedArray: any[] = [];
    arr.forEach((item) => {
        if (item instanceof Object) {
            // if Array item is { '...': <SD_HASH_DIGEST> }
            if (item[SD_LIST_PREFIX]) {
                const hash = item[SD_LIST_PREFIX];
                const disclosed = map[hash];
                if (disclosed) {
                    unpackedArray.push(unpack({ obj: disclosed.value, map }));
                }
            } else {
                // unpack recursively
                unpackedArray.push(unpack({ obj: item, map }));
            }
        } else {
            unpackedArray.push(item);
        }
    });
    return unpackedArray;
};
