import crypto from "crypto";
import { importJWK, jwtVerify, SignJWT } from "jose";

import { issueSDJWT } from "../sdjwt/index";
import { base64encode, decodeSDJWT, hasher } from "../sdjwt/index";
import { verifySDJWT } from "../sdjwt/index";
import { HOLDER_PRIVATE_KEY, HOLDER_PUBLIC_KEY, ISSUER_PRIVATE_KEY, ISSUER_PUBLIC_KEY } from "./mock/keys";

describe("SDJWT test", () => {
    let issuerSignedSdjwt: string;
    let holderSignedSdjwt: string;

    test("Issuer issue SDJWT to holder", async () => {
        try {
            const header = {
                alg: 'ES256',
                kid: 'issuer-key-id'
            };

            const payload = {
                "given_name": "John",
                "family_name": "Doe",
                "email": "johndoe@example.com",
                "phone_number": "+1-202-555-0101",
                "phone_number_verified": true,
                "address": {
                    "street_address": "123 Main St",
                    "locality": "Anytown",
                    "region": "Anystate",
                    "country": "US"
                },
                "emergency_phone_number": {
                    "first": "+1-202-555-0101",
                    "second": "+1-202-555-0102",
                },
                "birthdate": "1940-01-01",
                "updated_at": 1570000000,
                "nationalities": [
                    "US",
                    "DE"
                ],
                "iss": "https://issuer.example.com",
                "iat": 1683000000,
                "exp": 2883000000,
                "_sd_alg": "sha-256",
            };

            const disclosureFrame = {
                _sd: [],
            };

            const signer = async (header, payload) => {
                const issuerPrivateKey = await importJWK(ISSUER_PRIVATE_KEY, header.alg);
                const signature = await new SignJWT(payload).setProtectedHeader(header).sign(issuerPrivateKey);
                return signature.split('.').pop()!;
            };

            issuerSignedSdjwt = await issueSDJWT(header, payload, disclosureFrame, {
                hash: {
                    alg: 'sha-256',
                    callback: hasher,
                },
                signer,
            });
            expect(issuerSignedSdjwt).toBeDefined();
        } catch (error) {
            console.error(error);
            expect(false).toBe(true);
        }
    });

    test("Holder verify received SDJWT", async () => {
        try {
            const decodedSDJWT = decodeSDJWT(issuerSignedSdjwt);
            const header = decodedSDJWT.header;

            const verifier = async (jwt) => {
                const issuerPublickey = await importJWK(ISSUER_PUBLIC_KEY, header.alg);
                return !!jwtVerify(jwt, issuerPublickey);
            };
            const getHasher = (hashAlg) => {
                let hasher;
                // Default Hasher = Hasher for SHA-256
                if (!hashAlg || hashAlg.toLowerCase() === 'sha-256') {
                    hasher = (data) => {
                        const digest = crypto.createHash('sha256').update(data).digest();
                        return base64encode(digest);
                    };
                }
                return Promise.resolve(hasher);
            };
            const opts = {};

            const sdjwt = await verifySDJWT(issuerSignedSdjwt, verifier, getHasher, opts);
            expect(sdjwt).toBeDefined();
        } catch (error) {
            console.error(error);
            expect(false).toBe(true);
        }
    });

    test("Holder make SDJWT with selective disclosure", async () => {
        try {
            const decodedSDJWT = decodeSDJWT(issuerSignedSdjwt);
            const payload = decodedSDJWT.unverifiedInputSdJwt;

            const header = {
                alg: 'ES256',
                kid: 'holder-key-id'
            };

            const disclosureFrame = {
                nationalities: {
                    _sd: [0, 1],
                    _decoyCount: 2,
                },
                emergency_phone_number: {
                    _sd: ["first"],
                    _decoyCount: 1,
                },
                _sd: ["given_name", "family_name", "email", "phone_number", "address", "phone_number_verified", "birthdate", "updated_at"],
                _decoyCount: 3,
            };

            const signer = async (header, payload) => {
                const holderPrivateKey = await importJWK(HOLDER_PRIVATE_KEY, header.alg);
                return (await new SignJWT(payload).setProtectedHeader(header).sign(holderPrivateKey)).split('.').pop() ?? '';
            };

            holderSignedSdjwt = await issueSDJWT(header, payload, disclosureFrame, {
                hash: {
                    alg: 'sha-256',
                    callback: hasher,
                },
                signer,
                cnf: { jwk: HOLDER_PUBLIC_KEY },
                kbjwt: {
                    header: {
                        typ: "kb+jwt",
                        alg: "ES256",
                    },
                    payload: {
                        iat: 1683000000,
                        aud: "https://verifier.example.com",
                        nonce: "1",
                        sd_hash: crypto.createHash('sha256').update(issuerSignedSdjwt).digest('base64'),
                    },
                    signer: signer,
                },
            });
            expect(holderSignedSdjwt).toBeDefined();
            const { unverifiedInputSdJwt } = decodeSDJWT(holderSignedSdjwt);
            expect(unverifiedInputSdJwt.given_name).toBeUndefined();
            expect(unverifiedInputSdJwt.family_name).toBeUndefined();
            expect(unverifiedInputSdJwt.email).toBeUndefined();
            expect(unverifiedInputSdJwt.phone_number).toBeUndefined();
            expect(unverifiedInputSdJwt.address).toBeUndefined();
            expect(unverifiedInputSdJwt.phone_number_verified).toBeUndefined();
            expect(unverifiedInputSdJwt.birthdate).toBeUndefined();
            expect(unverifiedInputSdJwt.emergency_phone_number?.["first"]).toBeUndefined();
            expect(unverifiedInputSdJwt.emergency_phone_number?.["second"]).toBeDefined();
        } catch (error) {
            console.error(error);
            expect(false).toBe(true);
        }
    });

    test("Verify SDJWT with selective disclosure ", async () => {
        try {
            const decodedSDJWT = decodeSDJWT(holderSignedSdjwt);
            const header = decodedSDJWT.header;

            const verifier = async (jwt) => {
                const holderPublicKey = await importJWK(HOLDER_PUBLIC_KEY, header.alg);
                return !!jwtVerify(jwt, holderPublicKey);
            };

            const getHasher = (hashAlg) => {
                let hasher;
                // Default Hasher = Hasher for SHA-256
                if (!hashAlg || hashAlg.toLowerCase() === 'sha-256') {
                    hasher = (data) => {
                        const digest = crypto.createHash('sha256').update(data).digest();
                        return base64encode(digest);
                    };
                }
                return Promise.resolve(hasher);
            };
            const opts = {
                kb: {
                    verifier
                },
            };
            const sdjwtWithDisclosedClaims = await verifySDJWT(holderSignedSdjwt, verifier, getHasher, opts);
            console.log("sdjwtWithDisclosedClaims", sdjwtWithDisclosedClaims);
            expect(sdjwtWithDisclosedClaims).toBeDefined();
        } catch (error) {
            console.error(error);
            expect(false).toBe(true);
        }
    });
});
