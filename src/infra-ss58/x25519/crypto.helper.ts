import crypto from 'crypto';
import { Curve25519Converter } from './curve25519.converter';
import { PrivateJwk_ED, PublicJwk_ED } from '../ss58.interface';

export class EdToX25519Helper {
  static generateX25519KeyPairObject() {
    return crypto.generateKeyPairSync('x25519');
  }


  static edPkToX25519Pk(edPk: Uint8Array): Uint8Array {
    return Curve25519Converter.convertPublicKey(edPk);
  }
  static edToX25519PkJWK(edPk: Uint8Array): PublicJwk_ED {
    return this.key2JWK(EdToX25519Helper.edPkToX25519Pk(edPk));
  }

  static edSkToX25519Sk(edSk: Uint8Array): Uint8Array {
    return Curve25519Converter.convertSecretKey(edSk);
  }
  static edToX25519SkJWK(edPk: Uint8Array, edSk: Uint8Array): PrivateJwk_ED {
    return this.key2JWK(EdToX25519Helper.edPkToX25519Pk(edPk), EdToX25519Helper.edSkToX25519Sk(edSk)) as PrivateJwk_ED;
  }
  static edToX25519KeyPair(edPk: Uint8Array, edSk: Uint8Array) {
    return {
      publicKey: EdToX25519Helper.edPkToX25519Pk(edPk),
      privateKey: EdToX25519Helper.edSkToX25519Sk(edSk),
    };
  }
  static edToX25519KeyPairJWK(edPk: Uint8Array, edSk: Uint8Array) {
    return {
      publicKeyJWK: this.key2JWK(EdToX25519Helper.edPkToX25519Pk(edPk)),
      privateKeyJWK: this.key2JWK(
        EdToX25519Helper.edPkToX25519Pk(edPk),
        EdToX25519Helper.edSkToX25519Sk(edSk)
      ),
    };
  }

  static key2JWK(pk: Uint8Array, sk?: Uint8Array): PublicJwk_ED | PrivateJwk_ED {
    const jwk: any = {
      kty: 'OKP',
      crv: 'X25519',
      x: Buffer.from(pk).toString('base64url'),
    };
    if (sk) {
      jwk.d = Buffer.from(sk).toString('base64url');
    }
    return jwk;
  }
  private static jwk2KeyObject(key: PublicJwk_ED | PrivateJwk_ED, type: 'public' | 'private'): crypto.KeyObject {
    let res: crypto.KeyObject;

    if (type === 'public') {
      res = crypto.createPublicKey({ key, format: 'jwk' });
    } else {
      res = crypto.createPrivateKey({ key, format: 'jwk' });
    }
    return res;
  }
  static jwkToEcdhesKeypair(xPkJWK: PublicJwk_ED, xSkJWK: PrivateJwk_ED): Buffer {
    return crypto.diffieHellman({
      publicKey: this.jwk2KeyObject(xPkJWK, 'public'),
      privateKey: this.jwk2KeyObject(xSkJWK, 'private'),
    });
  }

}
