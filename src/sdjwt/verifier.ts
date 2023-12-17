import { unpackSDJWT } from "./common";
import { FORMAT_SEPARATOR } from "./constants";
import { GetHasher, SDJWTPayload,Verifier, VerifySdJwtOptions } from "./types";
import { decodeSDJWT } from "./utils";

export async function verifySDJWT(
    sdjwt: string,
    verifier: Verifier,
    getHasher: GetHasher,
    opts?: VerifySdJwtOptions,
): Promise<SDJWTPayload> {    
    const { unverifiedInputSdJwt: jwt, disclosures, keyBindingJWT } = decodeSDJWT(sdjwt);
    if (opts?.kb) {
        const kb = opts.kb;
        const holderPublicKey = jwt.cnf?.jwk;

        if (!holderPublicKey) {
            throw new Error('No holder public key in SD-JWT');
        }

        if (kb.verifier) {
            if (typeof kb.verifier !== 'function') {
                throw new Error('Invalid KB_JWT verifier function');
            }
            if (!keyBindingJWT) {
                throw new Error('No Key Binding JWT found');
            }

            try {
                const verifiedKBJWT = await kb.verifier(keyBindingJWT, holderPublicKey);
                if (!verifiedKBJWT) {
                    throw new Error('KB JWT is invalid');
                }
            } catch (e) {
                throw new Error('Failed to verify Key Binding JWT');
            }
        }
    }

    const compactJWT = sdjwt.split(FORMAT_SEPARATOR)[0];

    try {
        const verified = await verifier(compactJWT);
        if (!verified) {
            throw new Error('Failed to verify SD-JWT');
        }
    } catch (e) {
        throw new Error('Failed to verify SD-JWT');
    }

    return unpackSDJWT(jwt, disclosures, getHasher);
}