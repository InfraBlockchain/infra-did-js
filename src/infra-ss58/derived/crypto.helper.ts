import crypto from 'crypto';
import { Curve25519Converter } from './curve25519.converter';
import { PrivateJwk_ED, PublicJwk_ED } from '../ss58.interface';
import base64url from 'base64url';

export class CryptoHelper {
  static generateX25519KeyPairObject() {
    return crypto.generateKeyPairSync('x25519');
  }

  static edPkToX25519Pk(edPk: Uint8Array, format: 'u8a' | 'jwk' | 'keyObject'): Uint8Array | PublicJwk_ED | crypto.KeyObject {
    const xPk = Curve25519Converter.convertPublicKey(edPk);
    if (format === 'u8a') return xPk
    else if (format === 'jwk') return this.key2JWK('X25519', xPk);
    else if (format === 'keyObject') return this.jwk2KeyObject(this.key2JWK('X25519', xPk), 'public');
  }

  static edSkToX25519Sk(edPk: Uint8Array, edSk: Uint8Array, format: 'u8a' | 'jwk' | 'keyObject'): Uint8Array | PrivateJwk_ED | crypto.KeyObject {
    const xSk = Curve25519Converter.convertSecretKey(edSk);
    const xPk = Curve25519Converter.convertPublicKey(edPk);
    if (format === 'u8a') return xSk
    else if (format === 'jwk') return this.key2JWK('X25519', xPk, xSk) as PrivateJwk_ED;
    else if (format === 'keyObject') return this.jwk2KeyObject(this.key2JWK('X25519', xPk, xSk), 'private');
  }

  static edToX25519KeyPair(edPk: Uint8Array, edSk: Uint8Array): { publicKey: Uint8Array, privateKey: Uint8Array, publicKeyJWK: PublicJwk_ED, privateKeyJWK: PrivateJwk_ED } {
    const publicKey = CryptoHelper.edPkToX25519Pk(edPk, 'u8a') as Uint8Array;
    const privateKey = CryptoHelper.edSkToX25519Sk(edPk, edSk, 'u8a') as Uint8Array;

    return {
      publicKey,
      privateKey,
      publicKeyJWK: this.key2JWK('X25519', publicKey),
      privateKeyJWK: this.key2JWK('X25519', publicKey, privateKey) as PrivateJwk_ED,
    };
  }


  static key2JWK(crv: 'Ed25519' | 'X25519', pk: Uint8Array, sk?: Uint8Array): PublicJwk_ED | PrivateJwk_ED {
    const jwk: PublicJwk_ED = {
      alg: 'EdDSA',
      kty: 'OKP',
      crv,
      x: Buffer.from(pk).toString('base64url'),
    };
    if (sk) {
      return {
        ...jwk,
        d: Buffer.from(sk).toString('base64url')
      } as PrivateJwk_ED
    }
    return jwk as PublicJwk_ED
  }
  static jwk2Key(jwk: PublicJwk_ED | PrivateJwk_ED): { publicKey: Uint8Array, privateKey?: Uint8Array } {
    const publicKey = new Uint8Array(base64url.toBuffer(jwk.x));
    let privateKey: Uint8Array | undefined;
    if ((jwk as PrivateJwk_ED).d) {
      privateKey = new Uint8Array(base64url.toBuffer((jwk as PrivateJwk_ED).d));
    }
    return { publicKey, privateKey }
  }

  static jwk2KeyObject(key: PublicJwk_ED | PrivateJwk_ED, type: 'public' | 'private'): crypto.KeyObject {
    let res: crypto.KeyObject;

    if (type === 'public') {
      res = crypto.createPublicKey({ key, format: 'jwk' });
    } else {
      res = crypto.createPrivateKey({ key, format: 'jwk' });
    }
    return res;
  }
  static keyObject2JWK(key: crypto.KeyObject): PublicJwk_ED | PrivateJwk_ED {
    return {
      alg: 'EdDSA',
      ...key.export({ format: 'jwk' }) as PublicJwk_ED | PrivateJwk_ED
    }
  }



  static jwkToEcdhesKeypair(crv: 'Ed25519' | 'X25519', pk: Uint8Array | PublicJwk_ED | crypto.KeyObject, sk: Uint8Array | PrivateJwk_ED | crypto.KeyObject): Buffer {
    let publicKey: crypto.KeyObject
    let privateKey: crypto.KeyObject

    if (pk instanceof Uint8Array) {
      publicKey = this.jwk2KeyObject(this.key2JWK(crv, pk), 'public')
    }
    if (pk instanceof crypto.KeyObject) {
      publicKey = pk
    } else {
      publicKey = this.jwk2KeyObject(pk as PublicJwk_ED, 'public')
    }

    if (sk instanceof Uint8Array) {
      privateKey = this.jwk2KeyObject(this.key2JWK(crv, this.jwk2Key(this.keyObject2JWK(publicKey)).publicKey, sk), 'private')
    }
    if (sk instanceof crypto.KeyObject) {
      privateKey = sk
    } else {
      privateKey = this.jwk2KeyObject(sk as PrivateJwk_ED, 'private')
    }

    return crypto.diffieHellman({ publicKey, privateKey });
  }

}
