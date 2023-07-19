yarn run v1.22.19
$ jest ss58
  console.log
    didDocument(offchain):  {
      "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
      "controller": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm"
      ],
      "verificationMethod": [
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyBase58": "Gq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyMultibase": "zGq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3",
          "type": "JsonWebKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyJwk": {
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
            "x": "6zIBoQqrhq07Z3uhfK21pHhUxQa5Ax-6LFQhebs0jAM"
          }
        }
      ],
      "authentication": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "assertionMethod": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "keyAgreement": [],
      "capabilityInvocation": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "ATTESTS_IRI": null,
      "service": []
    }

      at src/__tests__/ss58-test.ts:106:25

  console.log
    didDocument(onChain):  {
      "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
      "controller": [
        "did:infra:space5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm"
      ],
      "verificationMethod": [
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyBase58": "Gq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyMultibase": "zGq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3",
          "type": "JsonWebKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyJwk": {
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "keys-3",
            "x": "6zIBoQqrhq07Z3uhfK21pHhUxQa5Ax-6LFQhebs0jAM"
          }
        }
      ],
      "authentication": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "assertionMethod": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "keyAgreement": [],
      "capabilityInvocation": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "ATTESTS_IRI": null,
      "service": []
    }

      at src/__tests__/ss58-test.ts:120:25

  console.log
    didDocument(onChain) after add keys:  {
      "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
      "controller": [
        "did:infra:space5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm"
      ],
      "verificationMethod": [
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyBase58": "Gq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyMultibase": "zGq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3",
          "type": "JsonWebKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyJwk": {
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "keys-3",
            "x": "6zIBoQqrhq07Z3uhfK21pHhUxQa5Ax-6LFQhebs0jAM"
          }
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-4",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyBase58": "63KJbRwvZ3GLtx3kQ9Dnw5Jdm15E1EQzpPd9TsT6tbyA"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-5",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyMultibase": "z63KJbRwvZ3GLtx3kQ9Dnw5Jdm15E1EQzpPd9TsT6tbyA"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-6",
          "type": "JsonWebKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyJwk": {
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "keys-6",
            "x": "SuJKuf5LEm6emfpkeZLKYgYlO_Ub1YE3vQr4culyDok"
          }
        }
      ],
      "authentication": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-4",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-5",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-6"
      ],
      "assertionMethod": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-4",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-5",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-6"
      ],
      "keyAgreement": [],
      "capabilityInvocation": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-4",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-5",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-6"
      ],
      "ATTESTS_IRI": null,
      "service": []
    }

      at src/__tests__/ss58-test.ts:129:29

  console.log
    didDocument(onChain) after remove keys:  {
      "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
      "controller": [
        "did:infra:space5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm"
      ],
      "verificationMethod": [
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyBase58": "Gq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyMultibase": "zGq732Fh5bnuTzH1wFFLWCPuXtebvTcBN2Aj5SViCWsMU"
        },
        {
          "id": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3",
          "type": "JsonWebKey2020",
          "controller": "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm",
          "publicKeyJwk": {
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "keys-3",
            "x": "6zIBoQqrhq07Z3uhfK21pHhUxQa5Ax-6LFQhebs0jAM"
          }
        }
      ],
      "authentication": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "assertionMethod": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "keyAgreement": [],
      "capabilityInvocation": [
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-1",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-2",
        "did:infra:space:5HP5xviDH4b3WUAX8UjqBqeqdHDULUZYTy5pEoc43bUbmwGm#keys-3"
      ],
      "ATTESTS_IRI": null,
      "service": []
    }

      at src/__tests__/ss58-test.ts:139:29

  console.log
    {
      sigSet: {
        params: SignatureParamsG1 { value: [Object], label: [Uint8Array] },
        publicKey: {
          bytes: '0xb650e56e55a5fb26a649f79e4bb435001f4e794219dfe5b5af0b92777ba1475b3c67cd71dcd01f19e6042aaf468801185e4e8807d2984de84b7096457133b08f05058a0e8014872d7d6c5c40ac74b2235d30600228d1528989a1c4ca1180ac16',
          paramsRef: undefined,
          curveType: 'Bls12381'
        },
        messageCounter: 1,
        label: undefined,
        keyPair: Bls12381G2KeyPairDock2022 {
          type: 'Bls12381G2VerificationKeyDock2022',
          id: undefined,
          controller: 'did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9',
          privateKeyBuffer: [Uint8Array],
          publicKeyBuffer: [Uint8Array]
        }
      }
    }

      at Object.<anonymous> (src/__tests__/ss58-test.ts:251:21)

  console.log
    bbs+ didDocument(onChain):  {
      "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9",
      "controller": [
        "did:infra:space5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9"
      ],
      "verificationMethod": [
        {
          "id": "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-1",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9",
          "publicKeyBase58": "8qam96JEoEmMYTL515Qz9Jo8eX38EbGyYy1Wt9vrGKsr"
        },
        {
          "id": "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-2",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9",
          "publicKeyMultibase": "z8qam96JEoEmMYTL515Qz9Jo8eX38EbGyYy1Wt9vrGKsr"
        },
        {
          "id": "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-3",
          "type": "JsonWebKey2020",
          "controller": "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9",
          "publicKeyJwk": {
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "keys-3",
            "x": "dHPcbLZp6x6eyCKPtbZNWy8oNe-_7g2kbUwybJtx2RU"
          }
        }
      ],
      "authentication": [
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-1",
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-2",
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-3"
      ],
      "assertionMethod": [
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-1",
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-2",
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-3"
      ],
      "keyAgreement": [],
      "capabilityInvocation": [
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-1",
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-2",
        "did:infra:space:5EhPq5NXnhMQYf9sq4bCqqpkGvomv2F9mNwPqtACsS4fY1E9#keys-3"
      ],
      "ATTESTS_IRI": null,
      "service": []
    }

      at src/__tests__/ss58-test.ts:262:25

Done in 97.76s.
