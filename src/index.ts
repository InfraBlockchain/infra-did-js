import { createJWT, Signer, SimpleSigner, toEthereumAddress, verifyJWT } from 'did-jwt'
import { Api, JsonRpc, Numeric } from 'eosjs'
import { JsSignatureProvider } from 'eosjs/dist/eosjs-jssig'
import { PublicKey } from 'eosjs/dist/PublicKey'
import { PrivateKey } from 'eosjs/dist/PrivateKey'
import { ec as EC } from 'elliptic'
// const EC = require('elliptic').ec
import fetch from 'node-fetch'

const secp256k1 = new EC('secp256k1') // currently only support secp256k1 key

interface IConfig {
  did: string
  privateKey: string // did controller key, currently only support secp256k1 key
  networkId: string
  registryContract: string
  rpcEndpoint: string
  jwtSigner?: any
}

export default class InfraDID {
  public did: string
  public didPubKey?: string
  public didAccount?: string

  private registryContract: string
  private jsonRpc: JsonRpc
  private api: Api
  private jwtSigner: Signer

  constructor (conf: IConfig) {
    this.did = conf.did
    const didSplit = conf.did.split(':')
    if (didSplit.length !== 3) {
      throw new Error(`invalid did, needs network identifier part and id part (${conf.did})`)
    }

    const idInNetwork = didSplit[2]

    if (idInNetwork.startsWith("PUB_K1_") || idInNetwork.startsWith("PUB_R1_") || idInNetwork.startsWith("EOS")) {
      this.didPubKey = idInNetwork
    } else {
      this.didAccount = idInNetwork
    }

    this.registryContract = conf.registryContract
    const rpc = new JsonRpc(conf.rpcEndpoint, { fetch } );
    this.jsonRpc = rpc

    const privKey = Numeric.stringToPrivateKey(conf.privateKey)
    if (privKey.type != Numeric.KeyType.k1 ) {
      throw new Error("unsupported private key type")
    }

    // const privKey: Numeric.Key = {
    //   type: Numeric.KeyType.k1,
    //   data: new Uint8Array(Buffer.from(conf.privateKeyHex, 'hex'))
    // }
    // const privateKeyBase58 = Numeric.privateKeyToString(privKey)
    const signatureProvider = new JsSignatureProvider([conf.privateKey]);
    this.api = new Api({ rpc, signatureProvider });

    if (conf.jwtSigner) {
      this.jwtSigner = conf.jwtSigner
    } else {
      const privateKeyHex = Buffer.from(privKey.data).toString('hex')
      this.jwtSigner = SimpleSigner(privateKeyHex)
    }
  }

  static createPubKeyDIDsecp256k1(networkId: string) : { did: string, publicKey: string, privateKey: string } {
    const ellipticKeyPair = secp256k1.genKeyPair();
    const publicKey = PublicKey.fromElliptic(ellipticKeyPair, Numeric.KeyType.k1, secp256k1).toString();
    const privateKey = PrivateKey.fromElliptic(ellipticKeyPair, Numeric.KeyType.k1, secp256k1).toString();
    const did = `did:infra:${networkId}:${publicKey}`

    return { did, publicKey, privateKey };
  }




  // async lookupOwner (cache = true) {
  //   if (cache && this.owner) return this.owner
  //   const result = await this.registry.identityOwner(this.address)
  //   return result['0']
  // }
  //
  // async changeOwner (newOwner) {
  //   const owner = await this.lookupOwner()
  //   const txHash = await this.registry.changeOwner(this.address, newOwner, {
  //     from: owner
  //   })
  //   this.owner = newOwner
  //   return txHash
  // }
  //
  // async addDelegate (delegate, {delegateType = Secp256k1VerificationKey2018, expiresIn = 86400}) {
  //   const owner = await this.lookupOwner()
  //   return this.registry.addDelegate(
  //     this.address,
  //     delegateType,
  //     delegate,
  //     expiresIn,
  //     { from: owner }
  //   )
  // }
  //
  // async revokeDelegate (delegate, delegateType = Secp256k1VerificationKey2018) {
  //   const owner = await this.lookupOwner()
  //   return this.registry.revokeDelegate(this.address, delegateType, delegate, {
  //     from: owner
  //   })
  // }
  //
  // async setAttribute (key, value, expiresIn = 86400, gasLimit) {
  //   const owner = await this.lookupOwner()
  //   return this.registry.setAttribute(
  //     this.address,
  //     stringToBytes32(key),
  //     attributeToHex(key, value),
  //     expiresIn,
  //     {
  //       from: owner,
  //       gas: gasLimit
  //     }
  //   )
  // }
  //
  // async revokeAttribute (key, value, gasLimit) {
  //   const owner = await this.lookupOwner()
  //   return this.registry.revokeAttribute(
  //     this.address,
  //     stringToBytes32(key),
  //     attributeToHex(key, value),
  //     {
  //       from: owner,
  //       gas: gasLimit
  //     }
  //   )
  // }
  //
  // // Create a temporary signing delegate able to sign JWT on behalf of identity
  // async createSigningDelegate (
  //   delegateType = Secp256k1VerificationKey2018,
  //   expiresIn = 86400
  // ) {
  //   const kp = EthrDID.createKeyPair()
  //   this.signer = SimpleSigner(kp.privateKey)
  //   const txHash = await this.addDelegate(kp.address, {
  //     delegateType,
  //     expiresIn
  //   })
  //   return { kp, txHash }
  // }

  async signJWT (payload, expiresIn?: number) {
    if (typeof this.jwtSigner !== 'function') {
      throw new Error('No signer configured')
    }
    const options = { signer: this.jwtSigner, alg: 'ES256K', issuer: this.did }
    if (expiresIn) options['expiresIn'] = expiresIn
    return createJWT(payload, options)
  }

  async verifyJWT (jwt, resolver, audience = this.did): Promise<any> {
    return verifyJWT(jwt, { resolver, audience })
  }
}
