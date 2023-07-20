import { SignatureParamsG1 } from "@docknetwork/crypto-wasm-ts";
import { hexToU8a, u8aToHex } from "@polkadot/util";
import InfraSS58 from "..";
import { HexString, BBSPlus_Params, CRYPTO_BBS_INFO, BBSPlus_PublicKey } from "../ss58.interface";

export class InfraSS58_BBS {
  did: string;
  constructor(private that: InfraSS58) {
    this.did = that.didModule.did
  }
  async createSigParamsByDID(paramCounter: number)
    : Promise<SignatureParamsG1> {
    const queriedParams = await this.getParams(paramCounter);
    const params1Val = SignatureParamsG1.valueFromBytes(hexToU8a(queriedParams?.bytes));
    return await new SignatureParamsG1(params1Val, hexToU8a(queriedParams?.label));
  }
  private async getParamsByHexDid(hexDid: HexString, paramCounter: number): Promise<BBSPlus_Params | null> {
    const resp = await this.that.api.query.bbsPlus.bbsPlusParams(hexDid, paramCounter);
    if (resp.isSome) {
      const params = resp.unwrap()
      return {
        bytes: u8aToHex(params.bytes),
        curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
        label: params.label.isSome ? u8aToHex(params.label.unwrap()) : null
      }
    }
    return null;
  }

  private async getPublicKeyByHexDid(hexDid: HexString, keyId: number, withParams = false): Promise<BBSPlus_PublicKey | null> {
    const resp = await this.that.api.query.bbsPlus.bbsPlusKeys(hexDid, keyId);
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
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const AddBBSPlusPublicKey = { key: publicKey, did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.addPublicKey(AddBBSPlusPublicKey, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removePublicKey(removeKeyId: number) {
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const RemoveBBSPlusPublicKey = { keyRef: [hexDID, removeKeyId], did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveBBSPlusPublicKey }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.removePublicKey(RemoveBBSPlusPublicKey, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getPublicKey(keyId: number, withParams = false): Promise<BBSPlus_PublicKey | null> {
    const hexId = InfraSS58.didToHex(this.did);
    return this.getPublicKeyByHexDid(hexId, keyId, withParams);
  }

  async addParams(sigParam: SignatureParamsG1, label?: string) {
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const params = {
      bytes: u8aToHex(sigParam.toBytes()),
      curveType: CRYPTO_BBS_INFO.CURVE_TYPE,
      label
    }
    const AddBBSPlusParams = { params, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddBBSPlusParams }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.addParams(AddBBSPlusParams, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removeParams(paramCounter: number) {
    const hexDID = InfraSS58.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const RemoveBBSPlusParams = { paramsRef: [hexDID, paramCounter], nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveBBSPlusParams }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.bbsPlus.removeParams(RemoveBBSPlusParams, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getParams(paramCounter: number): Promise<BBSPlus_Params | null> {
    const hexId = InfraSS58.didToHex(this.did);
    return await this.getParamsByHexDid(hexId, paramCounter);
  }

  async getLastParamsWritten(): Promise<BBSPlus_Params | null> {
    const hexId = InfraSS58.didToHex(this.did);
    const lastCounter: number = await this.that.api.query.bbsPlus.paramsCounter(hexId);
    if (lastCounter < 1) return null
    return await this.getParamsByHexDid(hexId, lastCounter)
  }

  async getAllParams(): Promise<BBSPlus_Params[]> {
    const hexId = InfraSS58.didToHex(this.did);
    const params: any = [];
    const lastCounter: number = await this.that.api.query.bbsPlus.paramsCounter(hexId);
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
