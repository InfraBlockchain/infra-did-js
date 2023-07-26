import { randomAsHex, blake2AsHex } from "@polkadot/util-crypto";
import { InfraSS58, BTreeSet, HexString, Codec } from "..";

export class InfraSS58_TrustedEntity {
  private owners: string[];


  constructor(private that: InfraSS58) {
    this.owners = [];
  }
  public createNewAuthorizerId(): HexString {
    return randomAsHex(32);
  }
  public getRevokeId(vcId): HexString {
    return blake2AsHex(vcId, 256);
  }
  public async registerAuthorizer(id: HexString, addOnly = false) {
    if (!this.owners || this.owners.length < 1) { this.addPolicyOwner() }
    const addAuthorizer = { id, newAuthorizer: { policy: this.getPolicyowner(), addOnly } };
    const tx = this.that.api.tx.trustedEntity.newAuthorizer(addAuthorizer);
    return this.that.signAndSend(tx, false, {});
  }


  public async unregisterAuthorizer(authorizerId) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    const removal = { authorizerId };
    const RemoveAuthorizer = { data: removal, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveAuthorizer }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.removeAuthorizer(removal, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async addIssuer(authorizerId, issuerDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(issuerDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const AddIssuer = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { AddIssuer }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.addIssuer(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async removeIssuer(authorizerId, issuerDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(issuerDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const RemoveIssuer = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveIssuer }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.removeIssuer(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async addVerifier(authorizerId, verifierDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(verifierDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const AddVerifier = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { AddVerifier }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.addVerifier(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async removeVerifier(authorizerId, verifierDID = this.that.didModule.did) {
    const hexDid = InfraSS58.didToHex(this.that.didModule.did);
    const nonce = await this.that.getNextNonce(hexDid);
    // @ts-ignore
    const entityIds = new BTreeSet();
    entityIds.add(InfraSS58.didToHex(verifierDID) as unknown as Codec)
    const entity = { authorizerId, entityIds };
    const RemoveVerifier = { data: entity, nonce, };
    const stateMessage = this.that.api.createType('StateChange', { RemoveVerifier }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const proof = [[controllerDIDSig, nonce]]
    const tx = this.that.api.tx.trustedEntity.removeVerifier(entity, proof);
    return this.that.signAndSend(tx, false, {});
  }

  public async getAuthorizer(authorizerId) {
    const resp = await this.that.api.query.trustedEntity.authorizers(authorizerId);
    if (resp.isNone) {
      throw new Error(`Could not find Authorizer: ${authorizerId}`);
    }
    return resp.unwrap();
  }
  public async getIssuers(authorizerId, issuerId) {
    const resp = await this.that.api.query.trustedEntity.issuers(authorizerId, InfraSS58.didToHex(issuerId));
    if (resp.isNone) {
      throw new Error(`Could not find issuers: ${issuerId}`);
    }
    return resp.unwrap();
  }
  public async getVerifiers(authorizerId, verifierId) {
    const resp = await this.that.api.query.trustedEntity.verifiers(authorizerId, InfraSS58.didToHex(verifierId));
    if (resp.isNone) {
      throw new Error(`Could not find issuers: ${verifierId}`);
    }
    return resp.unwrap();
  }

  public getPolicyowner() {
    return {
      OneOf: this.owners.sort(),
    }
  }
  public addPolicyOwner(ownerDID?: string) {
    ownerDID ??= this.that.didModule.did
    this.owners.push(InfraSS58.didToHex(ownerDID))
  }
}
