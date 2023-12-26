import { randomAsHex, blake2AsHex } from "@polkadot/util-crypto";
import type { InfraSS58, HexString } from "..";

export class InfraSS58_Revocation {
  private policyOwner: string[];

  constructor(private that: InfraSS58) {
    this.policyOwner = [];
  }
  public createNewRegistryId() {
    return randomAsHex(32);
  }
  public getRevokeId(vcId) {
    return blake2AsHex(vcId, 256);
  }
  public async registerRegistry(id: HexString, addOnly = false) {
    if (!this.policyOwner || this.policyOwner.length < 1) { this.addPolicyOwner() }
    const addReg = { id, newRegistry: { policy: this.getPolicyOwner(), addOnly } };
    const tx = this.that.api.tx.revoke.newRegistry(addReg);
    return this.that.signAndSend(tx, false, {});
  }

  public async revokeCredential(registryId, revId) {
    const hexDid = this.that.didToHexPk(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);

    const revoke = { registryId, revokeIds: [revId] };
    const Revoke = { data: revoke, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { Revoke }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]];
    const tx = this.that.api.tx.revoke.revoke(revoke, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async unrevokeCredential(registryId, revId) {
    const hexDid = this.that.didToHexPk(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);

    const unrevoke = { registryId, revokeIds: [revId] };
    const UnRevoke = { data: unrevoke, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { UnRevoke }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]];
    const tx = this.that.api.tx.revoke.unrevoke(unrevoke, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async unregisterRegistry(registryId) {
    const hexDid = this.that.didToHexPk(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);

    const removal = { registryId };
    const RemoveRegistry = { data: removal, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveRegistry }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]];
    const tx = this.that.api.tx.revoke.removeRegistry(removal, proof);
    return this.that.signAndSend(tx, false, {});
  }
  public async getRegistry(registryID) {
    const resp = await this.that.api.query.revoke.registries(registryID);
    if (resp.isNone) {
      throw new Error(`Could not find revocation registry: ${registryID}`);
    }
    return resp.unwrap();
  }
  public async getIsRevoked(registryId, revokeId) {
    const resp = await this.that.api.query.revoke.revocations(registryId, revokeId);
    return !resp.isNone;
  }
  public getPolicyOwner() {
    return {
      OneOf: this.policyOwner.sort(),
    }
  }
  public addPolicyOwner(ownerDID?: string) {
    ownerDID ??= this.that.didModule.did
    this.policyOwner.push(this.that.didToHexPk(ownerDID))
  }
}