import { BBSPlusSignatureParamsG1 } from "@docknetwork/crypto-wasm-ts";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import { HexString, BBSPlus_Params, CRYPTO_BBS_INFO, BBSPlus_PublicKey } from "../ss58.interface";
import type { InfraSS58 } from "..";
import { stringToHex } from "@polkadot/util";

export class InfraSS58_BBS {
  did: string;
  constructor(private that: InfraSS58) {
    this.did = that.didModule.did
  }
  async createSigParamsByDID(paramCounter: number)
    : Promise<BBSPlusSignatureParamsG1> {
    const queriedParams = await this.getParams(paramCounter);
    const params1Val = BBSPlusSignatureParamsG1.valueFromBytes(hexToU8a(queriedParams?.bytes));
    return await new BBSPlusSignatureParamsG1(params1Val, hexToU8a(queriedParams?.label));
  }
  private async getParamsByHexDid(hexDid: HexString, paramCounter: number): Promise<BBSPlus_Params | null> {
    const resp = await this.that.api.query.offchainSignatures.signatureParams(hexDid, paramCounter);
    if (resp.isSome) {
      const params = resp.unwrap()
      return {
        bytes: u8aToHex(params.bytes),
        curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
        label: params.label ? u8aToHex(params.label.unwrap()) : null
      }
    }
    return null;
  }

  private async getPublicKeyByHexDid(hexDid: HexString, keyId: number, withParams = false): Promise<BBSPlus_PublicKey | null> {
    const resp = await this.that.api.query.offchainSignatures.publicKeys(hexDid, keyId);
    if (resp.isSome) {
      const pk = resp.unwrap();
      let paramsRef: any = null
      if (pk.paramsRef.isSome) {
        const pr = pk.paramsRef.unwrap();
        paramsRef = [u8aToHex(pr[0]), pr[1].toNumber()]
      }
      const pkObj: BBSPlus_PublicKey = {
        bytes: u8aToHex(pk.bytes),
        curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
        paramsRef,
        params: null,
      };
      if (withParams) {
        if (pkObj.paramsRef === null) {
          throw new Error('No reference to parameters for the public key');
        } else if (pkObj.paramsRef) {
          const params = await this.getParamsByHexDid(pkObj.paramsRef[0], pkObj.paramsRef[1]);
          if (params === null) {
            throw new Error(`Parameters with reference (${pkObj.paramsRef[0]}, ${pkObj.paramsRef[1]}) not found on chain`);
          }
          pkObj.params = params;
        }
      }
      return pkObj;
    }
    return null;
  }

  async addPublicKey(publicKey: BBSPlus_PublicKey) {
    const hexDID = this.that.didToHexPk(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const AddOffchainSignaturePublicKey = { key: { BBSPlus: { curveType: publicKey.curveType, bytes: publicKey.bytes } }, did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddOffchainSignaturePublicKey }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.offchainSignatures.addPublicKey(AddOffchainSignaturePublicKey, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removePublicKey(removeKeyId: number) {
    const hexDID = this.that.didToHexPk(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const RemoveOffchainSignaturePublicKey = { keyRef: [hexDID, removeKeyId], did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveOffchainSignaturePublicKey }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.offchainSignatures.removePublicKey(RemoveOffchainSignaturePublicKey, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getPublicKey(keyId: number, withParams = false): Promise<BBSPlus_PublicKey | null> {
    const hexId = this.that.didToHexPk(this.did);
    return this.getPublicKeyByHexDid(hexId, keyId, withParams);
  }

  async addParams(sigParam: BBSPlusSignatureParamsG1, label?: string) {
    const hexDID = this.that.didToHexPk(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const params = {
      label: stringToHex(label),
      bytes: u8aToHex(sigParam.toBytes()),
      curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
    }
    const AddOffchainSignatureParams = { BBSPlus: { params }, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddOffchainSignatureParams }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.offchainSignatures.addParams(AddOffchainSignatureParams, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removeParams(paramCounter: number) {
    const hexDID = this.that.didToHexPk(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const paramsRef = [hexDID, paramCounter];
    const RemoveOffchainSignatureParams = { paramsRef, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveOffchainSignatureParams }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.offchainSignatures.removeParams(RemoveOffchainSignatureParams, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getParams(paramCounter: number): Promise<BBSPlus_Params | null> {
    const hexId = this.that.didToHexPk(this.did);
    return await this.getParamsByHexDid(hexId, paramCounter);
  }

  async getLastParamsWritten(): Promise<BBSPlus_Params | null> {
    const hexId = this.that.didToHexPk(this.did);
    const lastCounter: number = await this.that.api.query.offchainSignatures.paramsCounter(hexId);
    if (lastCounter < 1) return null
    return await this.getParamsByHexDid(hexId, lastCounter)
  }

  async getAllParams(): Promise<BBSPlus_Params[]> {
    const hexId = this.that.didToHexPk(this.did);
    const params: any = [];
    const lastCounter: number = await this.that.api.query.offchainSignatures.paramsCounter(hexId);
    if (lastCounter > 0) {
      for (let counter = 1; counter <= lastCounter; counter++) {
        const param = await this.getParamsByHexDid(hexId, counter);
        if (param !== null) {
          params.push(param);
        }
      }
    }
    return params;
  }

}
