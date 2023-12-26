# Infra DID Javascript Library

## READEME for SDJWT

[README for SDJWT](README_sdjwt.md)

### Issue SDJWT

```typescript
import crypto from "crypto";
import { importJWK, jwtVerify, SignJWT } from "jose";

import {
  issueSDJWT,
  base64encode,
  decodeSDJWT,
  hasher,
  verifySDJWT,
} from "infra-did-js";

const header = {
  alg: "ES256",
  kid: "issuer-key-id",
};

const payload = {
  given_name: "John",
  family_name: "Doe",
  email: "johndoe@example.com",
  phone_number: "+1-202-555-0101",
  phone_number_verified: true,
  address: {
    street_address: "123 Main St",
    locality: "Anytown",
    region: "Anystate",
    country: "US",
  },
  emergency_phone_number: {
    first: "+1-202-555-0101",
    second: "+1-202-555-0102",
  },
  birthdate: "1940-01-01",
  updated_at: 1570000000,
  nationalities: ["US", "DE"],
  iss: "https://issuer.example.com",
  iat: 1683000000,
  exp: 2883000000,
  _sd_alg: "sha-256",
};

const disclosureFrame = {
  _sd: [],
};

const signer = async (header, payload) => {
  const issuerPrivateKey = await importJWK(ISSUER_PRIVATE_KEY, header.alg);
  const signature = await new SignJWT(payload)
    .setProtectedHeader(header)
    .sign(issuerPrivateKey);
  return signature.split(".").pop()!;
};

const issuerSignedSdjwt = await issueSDJWT(header, payload, disclosureFrame, {
  hash: {
    alg: "sha-256",
    callback: hasher,
  },
  signer,
});
```

### Verify SDJWT

```typescript
import crypto from "crypto";
import { importJWK, jwtVerify, SignJWT } from "jose";

import {
  issueSDJWT,
  base64encode,
  decodeSDJWT,
  hasher,
  verifySDJWT,
} from "infra-did-js";

const decodedSDJWT = decodeSDJWT(issuerSignedSdjwt);
const header = decodedSDJWT.header;

const verifier = async (jwt) => {
  const issuerPublickey = await importJWK(ISSUER_PUBLIC_KEY, header.alg);
  return !!jwtVerify(jwt, issuerPublickey);
};
const getHasher = (hashAlg) => {
  let hasher;
  // Default Hasher = Hasher for SHA-256
  if (!hashAlg || hashAlg.toLowerCase() === "sha-256") {
    hasher = (data) => {
      const digest = crypto.createHash("sha256").update(data).digest();
      return base64encode(digest);
    };
  }
  return Promise.resolve(hasher);
};
const opts = {};

const sdjwt = await verifySDJWT(issuerSignedSdjwt, verifier, getHasher, opts);
```

### Issue SDJWT with disclosure

```typescript
import crypto from "crypto";
import { importJWK, jwtVerify, SignJWT } from "jose";

import {
  issueSDJWT,
  base64encode,
  decodeSDJWT,
  hasher,
  verifySDJWT,
} from "infra-did-js";

const payload = {
  given_name: "John",
  family_name: "Doe",
  email: "johndoe@example.com",
  phone_number: "+1-202-555-0101",
  phone_number_verified: true,
  address: {
    street_address: "123 Main St",
    locality: "Anytown",
    region: "Anystate",
    country: "US",
  },
  emergency_phone_number: {
    first: "+1-202-555-0101",
    second: "+1-202-555-0102",
  },
  birthdate: "1940-01-01",
  updated_at: 1570000000,
  nationalities: ["US", "DE"],
  iss: "https://issuer.example.com",
  iat: 1683000000,
  exp: 2883000000,
  _sd_alg: "sha-256",
};

const header = {
  alg: "ES256",
  kid: "holder-key-id",
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
  _sd: [
    "given_name",
    "family_name",
    "email",
    "phone_number",
    "address",
    "phone_number_verified",
    "birthdate",
    "updated_at",
  ],
  _decoyCount: 3,
};

const signer = async (header, payload) => {
  const holderPrivateKey = await importJWK(HOLDER_PRIVATE_KEY, header.alg);
  return (
    (
      await new SignJWT(payload)
        .setProtectedHeader(header)
        .sign(holderPrivateKey)
    )
      .split(".")
      .pop() ?? ""
  );
};

const holderSignedSdjwt = await issueSDJWT(header, payload, disclosureFrame, {
  hash: {
    alg: "sha-256",
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
      sd_hash: crypto
        .createHash("sha256")
        .update(issuerSignedSdjwt)
        .digest("base64"),
    },
    signer: signer,
  },
});
```


### Verify SDJWT with disclosure

```typescript
import crypto from "crypto";
import { importJWK, jwtVerify, SignJWT } from "jose";

import {
  issueSDJWT,
  base64encode,
  decodeSDJWT,
  hasher,
  verifySDJWT,
} from "infra-did-js";

const decodedSDJWT = decodeSDJWT(holderSignedSdjwt);
const header = decodedSDJWT.header;

const verifier = async (jwt) => {
  const holderPublicKey = await importJWK(HOLDER_PUBLIC_KEY, header.alg);
  return !!jwtVerify(jwt, holderPublicKey);
};

const getHasher = (hashAlg) => {
  let hasher;
  // Default Hasher = Hasher for SHA-256
  if (!hashAlg || hashAlg.toLowerCase() === "sha-256") {
    hasher = (data) => {
      const digest = crypto.createHash("sha256").update(data).digest();
      return base64encode(digest);
    };
  }
  return Promise.resolve(hasher);
};
const opts = {
  kb: {
    verifier,
  },
};
const sdjwtWithDisclosedClaims = await verifySDJWT(
  holderSignedSdjwt,
  verifier,
  getHasher,
  opts
);
```
