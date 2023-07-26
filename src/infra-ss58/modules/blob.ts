import { bufferToU8a, u8aToString, u8aToHex } from "@polkadot/util";
import { encodeAddress } from "@polkadot/util-crypto";
import { InfraSS58, Schema, DID_QUALIFIER } from "..";


export class InfraSS58_BLOB {
  that: InfraSS58;
  did: string;
  constructor(that: InfraSS58) {
    this.that = that;
    this.did = that.didModule.did
  }
  async writeSchemaOnChainByBlob(blobSchema) {
    const hexId = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexId);

    const AddBlob = {
      blob: { ...blobSchema, blob: this.that.getSerializedBlobValue(blobSchema.blob) },
      nonce
    };

    const stateMessage = this.that.api.createType('StateChange', { AddBlob }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.blobStore.new(AddBlob, controllerDIDSig);
    return this.that.signAndSend(tx, false, {})
  }

  async getSchema(blobId: string) {
    const hexId = Schema.getHexIdFromBlobId(blobId);

    const resp = await this.that.api.query.blobStore.blobs(hexId);
    if (resp.isNone) {
      throw new Error(`Blob ID (${blobId}) does not exist`);
    }
    const respTuple = resp.unwrap();
    if (respTuple.length === 2) {
      let chainValue: Uint8Array | object = bufferToU8a(respTuple[1]);
      const strValue = u8aToString(chainValue as Uint8Array);
      if (strValue.substring(0, 1) === '{') {
        chainValue = JSON.parse(strValue);
      }

      if (typeof chainValue === 'object' && !(chainValue instanceof Uint8Array)) {
        const ss58Id = encodeAddress(u8aToHex(respTuple[0]));
        const author = `${DID_QUALIFIER}${this.that.networkId}${ss58Id}`;
        return { schema: chainValue, id: blobId, author };
      }
      throw new Error('Incorrect schema format');
    }
  }
}
