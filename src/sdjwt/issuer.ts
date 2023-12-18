import { JWTHeaderParameters, JWTPayload } from "jose";

import { packSDJWT } from "./common";
import { SD_HASH_ALG, SD_JWT_TYPE } from "./constants";
import { DisclosureFrame, IssueSDJWTOptions } from "./types";
import { base64encode, combineSDJWT, generateSalt } from "./utils";

export async function issueSDJWT(
    header: JWTHeaderParameters,
    payload: JWTPayload,
    disclosureFrame: DisclosureFrame,
    opts: IssueSDJWTOptions,
): Promise<string> {
    let signedKbjwt: string;
    const { signer, hash, cnf, kbjwt } = opts;
    
    const { claims, disclosures } = await packSDJWT(payload, disclosureFrame, hash.callback, { generateSalt });

    const protectedHeader = {
        typ: SD_JWT_TYPE,
        ...header,
    };

    if (cnf) {
        claims.cnf = cnf;
    }

    claims[SD_HASH_ALG] = hash.alg;

    const signature = await signer(protectedHeader, claims);

    const jwt: string = [
        base64encode(JSON.stringify(protectedHeader)),
        base64encode(JSON.stringify(claims)),
        signature,
    ].join('.');

    if (kbjwt) { 
        const header = kbjwt.header;
        const payload = kbjwt.payload;
        const signer = kbjwt.signer;
        const signature = await signer(header, payload);
        const jwt: string = [
            base64encode(JSON.stringify(header)),
            base64encode(JSON.stringify(payload)),
            signature,
        ].join('.');
        signedKbjwt = jwt;
    }

    return combineSDJWT(jwt, disclosures, signedKbjwt);
}
