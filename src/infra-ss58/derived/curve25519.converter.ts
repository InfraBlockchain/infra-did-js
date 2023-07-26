/* eslint-disable no-ternary */
/* eslint-disable no-bitwise */
/* eslint-disable prefer-const */
import crypto from 'crypto';
// Ported in 2023 by evan kim(https://github.com/keispace)
// Public domain.
// Modified to utilize Node.js's native implementation of SHA512
// Convert to typescript
// Implementation derived from TweetNaCl version 20140427.
// Original source here: https://github.com/jjavery/ed25519-to-x25519
// See for details: http://tweetnacl.cr.yp.to/
export class Curve25519Converter {
  private static gf0 = this.gf();
  private static gf1 = this.gf([1]);
  private static D = this.gf([
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f,
    0x6cee, 0x5203,
  ]);
  private static I = this.gf([
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1,
    0x2480, 0x2b83,
  ]);

  // Converts Ed25519 public key to Curve25519 public key.
  // montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p
  static convertPublicKey(pk: Uint8Array): Uint8Array {
    const z = new Uint8Array(32),
      q = [this.gf(), this.gf(), this.gf(), this.gf()],
      a = this.gf(),
      b = this.gf();

    if (this.unpackneg(q, pk)) {
      throw new Error('invalid key');
      // return null;
    } // reject invalid key

    const y = q[1];

    this.addition(a, this.gf1, y);
    this.subtraction(b, this.gf1, y);
    this.inversion25519(b, b);
    this.multiplication(a, a, b);

    this.pack25519(z, a);
    return z;
  }

  // Converts Ed25519 secret key to Curve25519 secret key.
  static convertSecretKey(sk: Uint8Array): Uint8Array {
    const o = new Uint8Array(32);
    const hash = crypto.createHash('sha512');
    hash.update(sk);
    const d = hash.digest();
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    for (let i = 0; i < 32; i++) {
      o[i] = d[i];
    }
    for (let i = 0; i < 64; i++) {
      d[i] = 0;
    }
    return o;
  }

  static convertKeyPair(edKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array }): {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  } {
    const publicKey = this.convertPublicKey(edKeyPair.publicKey);
    if (!publicKey) {
      throw new Error('invalid key');
    }
    return {
      publicKey: publicKey,
      secretKey: this.convertSecretKey(edKeyPair.secretKey),
    };
  }

  private static gf(init?: number[]): Float64Array {
    const r = new Float64Array(16);
    if (init) {
      for (let i = 0; i < init.length; i++) {
        r[i] = init[i];
      }
    }
    return r;
  }
  private static car25519(o: Float64Array) {
    for (let i = 0; i < 16; i++) {
      o[i] += 65536;
      const c = Math.floor(o[i] / 65536);
      o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i === 15 ? 1 : 0);
      o[i] -= c * 65536;
    }
  }
  private static sel25519(p: Float64Array, q: Float64Array, b: number) {
    let t,
      c = ~(b - 1);
    for (let i = 0; i < 16; i++) {
      t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }
  private static unpack25519(o: Float64Array, n: Uint8Array) {
    for (let i = 0; i < 16; i++) {
      o[i] = n[2 * i] + (n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
  }
  private static addition(o: Float64Array, a: Float64Array, b: Float64Array) {
    for (let i = 0; i < 16; i++) {
      o[i] = (a[i] + b[i]) | 0;
    }
  }

  private static subtraction(o: Float64Array, a: Float64Array, b: Float64Array) {
    for (let i = 0; i < 16; i++) {
      o[i] = (a[i] - b[i]) | 0;
    }
  }

  private static multiplication(o: Float64Array, a: Float64Array, b: Float64Array) {
    let t = new Float64Array(31);
    for (let i = 0; i < 31; i++) {
      t[i] = 0;
    }
    for (let i = 0; i < 16; i++) {
      for (let j = 0; j < 16; j++) {
        t[i + j] += a[i] * b[j];
      }
    }
    for (let i = 0; i < 15; i++) {
      t[i] += 38 * t[i + 16];
    }
    for (let i = 0; i < 16; i++) {
      o[i] = t[i];
    }
    this.car25519(o);
    this.car25519(o);
  }

  private static squaring(o: Float64Array, a: Float64Array) {
    this.multiplication(o, a, a);
  }

  private static inversion25519(o: Float64Array, i: Float64Array) {
    const c = this.gf();
    let a;
    for (a = 0; a < 16; a++) {
      c[a] = i[a];
    }
    for (a = 253; a >= 0; a--) {
      this.squaring(c, c);
      if (a !== 2 && a !== 4) {
        this.multiplication(c, c, i);
      }
    }
    for (a = 0; a < 16; a++) {
      o[a] = c[a];
    }
  }

  private static pack25519(o: Uint8Array, n: Float64Array) {
    let i, j, b;
    const m = this.gf(),
      t = this.gf();
    for (i = 0; i < 16; i++) {
      t[i] = n[i];
    }
    this.car25519(t);
    this.car25519(t);
    this.car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (m[15] >> 16) & 1;
      m[14] &= 0xffff;
      this.sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = t[i] >> 8;
    }
  }

  private static par25519(a: Float64Array) {
    const d = new Uint8Array(32);
    this.pack25519(d, a);
    return d[0] & 1;
  }

  private static crypto_verify(x: Uint8Array, xi: number, y: Uint8Array, yi: number, n: 32) {
    let d = 0;
    for (let i = 0; i < n; i++) {
      d |= x[xi + i] ^ y[yi + i];
    }
    return (1 & ((d - 1) >>> 8)) - 1;
  }

  private static crypto_verify_32(x: Uint8Array, xi: number, y: Uint8Array, yi: number) {
    return this.crypto_verify(x, xi, y, yi, 32);
  }

  private static neq25519(a: Float64Array, b: Float64Array) {
    const c = new Uint8Array(32),
      d = new Uint8Array(32);
    this.pack25519(c, a);
    this.pack25519(d, b);
    return this.crypto_verify_32(c, 0, d, 0);
  }

  private static pow2523(o: Float64Array, i: Float64Array) {
    const c = this.gf();
    let a;
    for (a = 0; a < 16; a++) {
      c[a] = i[a];
    }
    for (a = 250; a >= 0; a--) {
      this.squaring(c, c);
      if (a !== 1) {
        this.multiplication(c, c, i);
      }
    }
    for (a = 0; a < 16; a++) {
      o[a] = c[a];
    }
  }

  private static set25519(r: Float64Array, a: Float64Array) {
    for (let i = 0; i < 16; i++) {
      r[i] = a[i] | 0;
    }
  }

  private static unpackneg(r: Float64Array[], p: Uint8Array) {
    const t = this.gf(),
      chk = this.gf(),
      num = this.gf(),
      den = this.gf(),
      den2 = this.gf(),
      den4 = this.gf(),
      den6 = this.gf();

    this.set25519(r[2], this.gf1);
    this.unpack25519(r[1], p);
    this.squaring(num, r[1]);
    this.multiplication(den, num, this.D);
    this.subtraction(num, num, r[2]);
    this.addition(den, r[2], den);

    this.squaring(den2, den);
    this.squaring(den4, den2);
    this.multiplication(den6, den4, den2);
    this.multiplication(t, den6, num);
    this.multiplication(t, t, den);

    this.pow2523(t, t);
    this.multiplication(t, t, num);
    this.multiplication(t, t, den);
    this.multiplication(t, t, den);
    this.multiplication(r[0], t, den);

    this.squaring(chk, r[0]);
    this.multiplication(chk, chk, den);
    if (this.neq25519(chk, num)) {
      this.multiplication(r[0], r[0], this.I);
    }

    this.squaring(chk, r[0]);
    this.multiplication(chk, chk, den);
    if (this.neq25519(chk, num)) {
      return -1;
    }

    if (this.par25519(r[0]) === p[31] >> 7) {
      this.subtraction(r[0], this.gf0, r[0]);
    }

    this.multiplication(r[3], r[0], r[1]);
    return 0;
  }
}
