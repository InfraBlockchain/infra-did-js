import { u8aToHex } from "@polkadot/util";
import { randomAsHex } from "@polkadot/util-crypto";
import { Codec, DidKey_SS58, BTreeSet, IConfig_SS58, KeyringPair, PublicKey_SS58, ServiceEndpointType, VerificationRelationship, DIDSet } from "../ss58.interface";
import type { InfraSS58 } from "..";


export class InfraSS58_DID {

  private verRels: VerificationRelationship;
  did: string;
  keyPairs: KeyringPair[];
  private publicKey: PublicKey_SS58;

  private didKey: DidKey_SS58;

  private that: InfraSS58;
  challenge: any;


  private constructor(that: InfraSS58) { this.that = that }
  static async createAsync(conf: IConfig_SS58, apiModule: InfraSS58, didSet: DIDSet): Promise<InfraSS58_DID> {
    return await new InfraSS58_DID(apiModule).initModule(conf, didSet)
  }
  private async initModule(conf: IConfig_SS58, didSet: DIDSet): Promise<InfraSS58_DID> {
    this.verRels = conf.verRels || new VerificationRelationship()
    if (conf.seed) {
      const { did, didKey, keyPair, publicKey } = didSet; //await InfraSS58.createNewSS58DIDSet(conf.networkId, conf.cryptoInfo, conf.seed, conf.verRels)
      this.did = did;
      this.keyPairs = [keyPair];
      this.publicKey = publicKey;
      this.didKey = didKey;
    } else if (conf.keyPair) {
      this.keyPairs = [conf.keyPair];
      this.did = conf.did;
      this.publicKey = PublicKey_SS58.fromKeyringPair(this.keyPairs[0]);
      this.didKey = new DidKey_SS58(this.publicKey, this.verRels);
    } else {
      throw new Error("seed or keyPair required");
    }
    if (this.did !== conf.did) {
      throw new Error("DID does not match the given seed or keyPair.");
    }
    this.challenge = randomAsHex(32);

    this.that.controllerDID ??= this.did;
    this.that.controllerKeyPair ??= this.keyPairs[0]
    this.that.accountKeyPair ??= this.keyPairs[0]
    return this
  }

  async getDocument(getBbsPlusSigKeys = true) {
    return this.that.getDocument(this.did, getBbsPlusSigKeys)
  }

  public async getKeyDoc() {
    const doc = await this.getDocument()
    const verificationMethod = doc.verificationMethod.find(method => method.type === this.that.cryptoInfo.KEY_NAME)

    return this.that.getKeyDoc(verificationMethod.id, this.did, this.that.cryptoInfo.KEY_NAME, this.keyPairs[0])
  }
  async registerDIDOnChain(did: string, didKey, controllerDID?: string) {
    const hexId = this.that.didToHex(did);
    const didKeys = [didKey].map((d) => d.toJSON ? d.toJSON() : d);
    // @ts-ignore
    const controllers = new BTreeSet();
    controllers.add(this.that.didToHex(controllerDID) as unknown as Codec)

    const tx = await this.that.api.tx.didModule.newOnchain(hexId, didKeys, controllers);
    return this.that.signAndSend(tx, false, {});
  }
  async registerOnChain() {
    return await this.registerDIDOnChain(this.did, this.didKey, this.that.controllerDID);
  }

  async unregisterDIDOnChain(did, controllerDID, controllerSigType, contollerKeyPair) {
    const hexDID = this.that.didToHex(did)
    const nonce = await this.that.getNextNonce(hexDID);
    const DidRemoval = { did: hexDID, nonce };
    const stateMessage = this.that.api.createType('StateChange', { DidRemoval }).toU8a();
    const controllerDIDSig = this.that.getDIDSig(controllerDID, controllerSigType, contollerKeyPair, stateMessage)
    const tx = await this.that.api.tx.didModule.removeOnchainDid(DidRemoval, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }
  async unregisterOnChain() {
    return this.unregisterDIDOnChain(this.did, this.that.controllerDID, this.that.cryptoInfo.SIG_TYPE, this.keyPairs[0]);
  }

  async addKeys(...didKeys: DidKey_SS58[]) {
    const hexDID = this.that.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    const keys = didKeys.map((d) => d.toJSON());
    const AddKeys = { did: hexDID, keys, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddKeys }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);

    const tx = await this.that.api.tx.didModule.addKeys(AddKeys, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {})
  }

  async removeKeys(...keyIds: number[]) {
    const hexDID = this.that.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    // @ts-ignore
    const keys = new BTreeSet();
    keyIds.forEach((keyId: unknown) => {
      keys.add(keyId as Codec);
    });
    const RemoveKeys = { did: hexDID, keys, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveKeys }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = await this.that.api.tx.didModule.removeKeys(RemoveKeys, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {})
  }

  async addControllers(...controllerDIDs: string[]) {
    const hexDID = this.that.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    // @ts-ignore
    const controllers = new BTreeSet();
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = this.that.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });
    const AddControllers = { did: hexDID, controllers, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddControllers }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.addControllers(AddControllers, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {});
  }

  async removeControllers(...controllerDIDs: string[]) {
    const hexDID = this.that.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    // @ts-ignore
    const controllers = new BTreeSet();
    controllerDIDs.forEach((controllerDID) => {
      const controllerHexDID: unknown = this.that.didToHex(controllerDID);
      controllers.add(controllerHexDID as Codec);
    });
    const RemoveControllers = { did: hexDID, controllers, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveControllers }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.removeControllers(RemoveControllers, controllerDIDSig);
    return await this.that.signAndSend(tx, false, {});
  }

  async addServiceEndpoint(
    originsTexts: string[],
    endpointType?: ServiceEndpointType,
    endpointIdText?: string,
  ) {
    const encoder = new TextEncoder();
    const hexDID = this.that.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    if (!endpointType) {
      endpointType = new ServiceEndpointType()
      endpointType.setLinkedDomains()
    }
    const origins = originsTexts.map((u) => u8aToHex(encoder.encode(u)));
    const endpoint = { types: endpointType.value, origins };
    const hexID = u8aToHex(encoder.encode(endpointIdText));
    const AddServiceEndpoint = { did: hexDID, id: hexID, endpoint, nonce };
    const stateMessage = this.that.api.createType('StateChange', { AddServiceEndpoint }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.addServiceEndpoint(AddServiceEndpoint, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async removeServiceEndpoint(endpointIdText?: string) {
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    const spId = u8aToHex(encoder.encode(endpointIdText));
    const hexDID = this.that.didToHex(this.did)
    const nonce = await this.that.getNextNonce(hexDID);
    const RemoveServiceEndpoint = { did: hexDID, id: spId, nonce };
    const stateMessage = this.that.api.createType('StateChange', { RemoveServiceEndpoint }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.didModule.removeServiceEndpoint(RemoveServiceEndpoint, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }

  async getServiceEndpoint(endpointIdText?: string) {
    const hexDID = this.that.didToHex(this.did);
    const encoder = new TextEncoder();
    if (!endpointIdText) endpointIdText = `${this.did}#linked-domain`;
    const spId = u8aToHex(encoder.encode(endpointIdText));
    let resp = await this.that.api.query.didModule.didServiceEndpoints(hexDID, spId,);
    if (resp.isNone) {
      throw new Error(
        `No service endpoint found for did ${this.did} and with id ${endpointIdText}`,
      );
    }
    resp = resp.unwrap();
    return {
      type: new ServiceEndpointType(resp.types.toNumber()),
      origins: resp.origins.map((origin) => u8aToHex(origin)),
    };
  }

  async isController(controllerDID: string): Promise<boolean> {
    const controlledHexId = this.that.didToHex(this.did);
    const controllerHexId = this.that.didToHex(controllerDID);
    const resp = await this.that.api.query.didModule.didControllers(
      controlledHexId,
      controllerHexId,
    );
    return resp.isSome;
  }
  async setClaim(priority: number, iri: string) {
    const encoder = new TextEncoder();
    const hexDID = this.that.didToHex(this.did);
    const nonce = await this.that.getNextNonce(hexDID);
    const attest = { priority, iri: u8aToHex(encoder.encode(iri)) };
    const SetAttestationClaim = { attest, nonce };
    const stateMessage = this.that.api.createType('StateChange', { SetAttestationClaim }).toU8a();
    const controllerDIDSig = this.that.getControllerDIDSig(stateMessage);
    const tx = this.that.api.tx.attest.setClaim(SetAttestationClaim, controllerDIDSig);
    return this.that.signAndSend(tx, false, {});
  }
}
