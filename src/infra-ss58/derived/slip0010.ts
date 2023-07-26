import crypto from 'crypto';

import { hexToU8a } from '@polkadot/util/hex/toU8a';
import { stringToU8a } from '@polkadot/util/string/toU8a';
import { u8aToHex } from '@polkadot/util/u8a/toHex';
import { InfraSS58, HexString } from '..';




export interface DerivedEd25519KeySet {
  path: string,
  sk: Uint8Array,
  pk: Uint8Array,
  chainCode: Uint8Array,
}
export class DerivedEd25519Key {
  static privdev = 0x80000000;
  private static seedmodifier = 'ed25519 seed';

  private static seed2hdnode(data: Uint8Array, seed: Uint8Array): [Uint8Array, Uint8Array] {
    const h = crypto.createHmac('sha512', seed).update(data).digest();
    const key = h.subarray(0, 32);
    const chaincode = h.subarray(32);
    return [key, chaincode];
  }
  private static async derive(parent_key: Uint8Array, parent_chaincode: Uint8Array, i: number): Promise<[Uint8Array, Uint8Array]> {
    if (parent_key.length !== 32 || parent_chaincode.length !== 32) {
      throw new Error('length error');
    }
    const init_key = new Uint8Array(1);
    init_key.set([0x00]);
    const iarr = hexToU8a(i.toString(16));
    const d = new Uint8Array(init_key.length + parent_key.length + iarr.length);
    d.set(init_key);
    d.set(parent_key, init_key.length);
    d.set(iarr, init_key.length + parent_key.length);
    return this.seed2hdnode(d, parent_chaincode);
  }
  static fingerprint(pk: string): string {
    const sha256pk = crypto.createHash('sha256').update(hexToU8a(`0x${pk}`)).digest('hex');
    const pk160 = crypto.createHash('ripemd160').update(hexToU8a(sha256pk)).digest('hex');
    return pk160.slice(0, 8);
  }

  static async getMasterKey(seed: HexString): Promise<DerivedEd25519KeySet> {
    const [k, c] = this.seed2hdnode(hexToU8a(seed), stringToU8a(this.seedmodifier));
    const { publicKey } = await InfraSS58.createNewSS58DIDSet('space', undefined, u8aToHex(k));
    return {
      path: 'm',
      chainCode: c,
      sk: k,
      pk: hexToU8a(publicKey.toJSON()['Ed25519'])
    };
  }
  static async getDeriveKey(parentKey: Uint8Array, parentChainCode: Uint8Array, parentPath: string, derivationpath: number): Promise<DerivedEd25519KeySet> {
    derivationpath = (derivationpath | this.privdev) >>> 0;
    const path = parentPath + `/${derivationpath & (this.privdev - 1)}h`;
    const [k, c] = await this.derive(parentKey, parentChainCode, derivationpath);
    const { publicKey } = await InfraSS58.createNewSS58DIDSet('space', undefined, u8aToHex(k));
    return {
      path,
      chainCode: c,
      sk: k,
      pk: hexToU8a(publicKey.toJSON()['Ed25519'])
    };
  }


}