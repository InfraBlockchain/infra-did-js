import { createJWT, Signer, SimpleSigner, verifyJWT } from 'did-jwt'
import { Api, JsonRpc, Numeric } from 'eosjs'
import { JsSignatureProvider } from 'eosjs/dist/eosjs-jssig'
import { SerialBuffer } from 'eosjs/dist/eosjs-serialize'
import { PublicKey } from 'eosjs/dist/PublicKey'
import { PrivateKey } from 'eosjs/dist/PrivateKey'
import fetch from 'node-fetch'
import { ec as EC } from 'elliptic'
import { Buffer } from 'buffer'
// const EC = require('elliptic').ec

const secp256k1 = new EC('secp256k1') // currently only support secp256k1 key

const defaultPubKeyDidSignDataPrefix = "infra-mainnet"

interface IConfig {
  did: string
  didOwnerPrivateKey: string // did controller key, currently only supports secp256k1 key, in EOSIO base58 format
  networkId: string
  registryContract: string
  rpcEndpoint: string
  jwtSigner?: any
  txfeePayerAccount?: string
  txfeePayerPrivateKey?: string
  pubKeyDidSignDataPrefix?: string
}

export default class InfraDID {
  public did: string
  public didPubKey?: string
  public didAccount?: string
  private didOwnerPrivateKeyObj: PrivateKey

  private registryContract: string
  private jsonRpc: JsonRpc
  private api: Api
  private jwtSigner: Signer
  private txfeePayerAccount?: string
  private pubKeyDidSignDataPrefix: string

  constructor (conf: IConfig) {
    this.did = conf.did
    const didSplit = conf.did.split(':')
    if (didSplit.length !== 4) {
      throw new Error(`invalid did, needs network identifier part and id part (${conf.did})`)
    }

    const idInNetwork = didSplit[3]

    if (idInNetwork.startsWith("PUB_K1_") || idInNetwork.startsWith("PUB_R1_") || idInNetwork.startsWith("EOS")) {
      this.didPubKey = idInNetwork
    } else {
      this.didAccount = idInNetwork
    }

    this.registryContract = conf.registryContract
    const rpc = new JsonRpc(conf.rpcEndpoint, { fetch } );
    this.jsonRpc = rpc

    const privKey = Numeric.stringToPrivateKey(conf.didOwnerPrivateKey)
    if (privKey.type != Numeric.KeyType.k1 ) {
      throw new Error("unsupported private key type")
    }

    this.didOwnerPrivateKeyObj = PrivateKey.fromString(conf.didOwnerPrivateKey, secp256k1) //secp256k1.keyFromPrivate(this.privKey)

    const sigProviderPrivKeys = [conf.didOwnerPrivateKey]
    if (conf.txfeePayerAccount && conf.txfeePayerPrivateKey) {
      sigProviderPrivKeys.push(conf.txfeePayerPrivateKey)
      this.txfeePayerAccount = conf.txfeePayerAccount
    }
    if (this.didPubKey && !this.txfeePayerAccount) {
      throw new Error('tx fee payer account not configured for public key DID')
    }

    this.pubKeyDidSignDataPrefix = conf.pubKeyDidSignDataPrefix || defaultPubKeyDidSignDataPrefix

    const signatureProvider = new JsSignatureProvider(sigProviderPrivKeys);
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

  private async getNonceForPubKeyDid() : Promise<number> {
    const pubKey = Numeric.stringToPublicKey(this.didPubKey)
    const pubkey_index_256bits = Buffer.from(pubKey.data.slice(1,pubKey.data.length)).toString('hex')

    const options = {
      json: true,
      code: this.registryContract,
      scope: this.registryContract,
      table: 'pubkeydid',
      index_position: 2,
      key_type: 'sha256',
      lower_bound: pubkey_index_256bits,
      upper_bound: pubkey_index_256bits,
      limit: 1
    }

    const res = await this.jsonRpc.get_table_rows(options)
    if (res && res.rows.length > 0 && res.rows[0].nonce) {
      return res.rows[0].nonce
    } else {
      return 0
    }
  }

  private newSerialBuffer(dataLength: number) : SerialBuffer {
    const buf = new SerialBuffer({
      textEncoder: this.api.textEncoder,
      textDecoder: this.api.textDecoder,
      array: new Uint8Array(dataLength)
    })
    buf.length = 0
    return buf
  }

  private digestForPubKeyDIDSetAttributeSig(pubKey: string, key: string, value: string, nonce: number) {
    const actionName = "pksetattr"
    const dataLength = this.pubKeyDidSignDataPrefix.length + actionName.length + (1 + Numeric.publicKeyDataSize) + 2 + key.length + value.length

    const buf = this.newSerialBuffer(dataLength)
    buf.pushArray(buf.textEncoder.encode(this.pubKeyDidSignDataPrefix))
    buf.pushArray(buf.textEncoder.encode(actionName))
    buf.pushPublicKey(pubKey)
    buf.pushUint16(nonce)
    buf.pushArray(buf.textEncoder.encode(key))
    buf.pushArray(buf.textEncoder.encode(value))

    // console.log({data: buf.array})

    const digest = secp256k1.hash().update(buf.array).digest()
    return digest
  }

  async setAttributePubKeyDID(key: string, value: string) {

    if (!this.didPubKey) {
      throw new Error('public key did is not configured')
    }

    const nonce = await this.getNonceForPubKeyDid()
    const digest = this.digestForPubKeyDIDSetAttributeSig(this.didPubKey, key, value, nonce)
    const signature = this.didOwnerPrivateKeyObj.sign(digest, false)

    // console.log({nonce, digest, signature: signature.toString()})

    // [[eosio::action]]
    // void pksetattr( const public_key& pk, const string& key, const string& value, const signature& sig, const name& ram_payer );

    return await this.api.transact({
      actions: [{
        account: this.registryContract,
        name: 'pksetattr',
        authorization: [{
          actor: this.txfeePayerAccount,
          permission: 'active'
        }],
        data: {
          pk: this.didPubKey,
          key,
          value,
          sig: signature.toString(), // ex, SIG_K1_KkLuqSPgkvVT2udyy1PUs94ufraBvUd2C8KdcVrxQ8LptrSK7UAzRfFtphPT4wEqveJNAAh8JcvYyZUNTqinNeT9yZz7Sr
          ram_payer: this.txfeePayerAccount
        }
      }]
    }, {
      blocksBehind: 3,
      expireSeconds: 30
    })
  }

  private digestForPubKeyDIDChangeOwnerSig(pubKey: string, newOwnerPubKey: string, nonce: number) {
    const actionName = "pkchowner"
    const dataLength = this.pubKeyDidSignDataPrefix.length + actionName.length + (1 + Numeric.publicKeyDataSize) + 2 + (1 + Numeric.publicKeyDataSize)

    const buf = this.newSerialBuffer(dataLength)
    buf.pushArray(buf.textEncoder.encode(this.pubKeyDidSignDataPrefix))
    buf.pushArray(buf.textEncoder.encode(actionName))
    buf.pushPublicKey(pubKey)
    buf.pushUint16(nonce)
    buf.pushPublicKey(newOwnerPubKey)

    // console.log({data: buf.array})

    const digest = secp256k1.hash().update(buf.array).digest()
    return digest
  }

  async changeOwnerPubKeyDID(newOwnerPubKey: string) {
    if (!this.didPubKey) {
      throw new Error('public key did is not configured')
    }

    const nonce = await this.getNonceForPubKeyDid()
    const digest = this.digestForPubKeyDIDChangeOwnerSig(this.didPubKey, newOwnerPubKey, nonce)
    const signature = this.didOwnerPrivateKeyObj.sign(digest, false)

    console.log({nonce, digest, signature: signature.toString()})

    // [[eosio::action]]
    // void pkchowner( const public_key& pk, const public_key& new_owner_pk, const signature& sig, const name& ram_payer );

    return await this.api.transact({
      actions: [{
        account: this.registryContract,
        name: 'pkchowner',
        authorization: [{
          actor: this.txfeePayerAccount,
          permission: 'active'
        }],
        data: {
          pk: this.didPubKey,
          new_owner_pk: newOwnerPubKey,
          sig: signature.toString(),
          ram_payer: this.txfeePayerAccount
        }
      }]
    }, {
      blocksBehind: 3,
      expireSeconds: 30
    })
  }

  private digestForPubKeyDIDRevokeSig(pubKey: string, nonce: number) {
    const actionName = "pkdidrevoke"
    const dataLength = this.pubKeyDidSignDataPrefix.length + actionName.length + (1 + Numeric.publicKeyDataSize) + 2

    const buf = this.newSerialBuffer(dataLength)
    buf.pushArray(buf.textEncoder.encode(this.pubKeyDidSignDataPrefix))
    buf.pushArray(buf.textEncoder.encode(actionName))
    buf.pushPublicKey(pubKey)
    buf.pushUint16(nonce)

    console.log({data: buf.array, dataUtf8: new TextDecoder().decode(buf.array)})

    const digest = secp256k1.hash().update(buf.array).digest()
    return digest
  }

  async revokePubKeyDID() {
    // return this.changeOwnerPubKeyDID('PUB_K1_11111111111111111111111111111111149Mr2R') // set dead key (33 bytes zero value) as new owner key

    if (!this.didPubKey) {
      throw new Error('public key did is not configured')
    }

    const nonce = await this.getNonceForPubKeyDid()
    const digest = this.digestForPubKeyDIDRevokeSig(this.didPubKey, nonce)
    const signature = this.didOwnerPrivateKeyObj.sign(digest, false)

    console.log({nonce, digest, signature: signature.toString()})

    // [[eosio::action]]
    // void pkrevokedid( const public_key& pk, const signature& sig, const name& ram_payer );

    return await this.api.transact({
      actions: [{
        account: this.registryContract,
        name: 'pkdidrevoke',
        authorization: [{
          actor: this.txfeePayerAccount,
          permission: 'active'
        }],
        data: {
          pk: this.didPubKey,
          sig: signature.toString(),
          ram_payer: this.txfeePayerAccount
        }
      }]
    }, {
      blocksBehind: 3,
      expireSeconds: 30
    })
  }

  private digestForPubKeyDIDClearSig(pubKey: string, nonce: number) {
    const actionName = "pkdidclear"
    const dataLength = this.pubKeyDidSignDataPrefix.length + actionName.length + (1 + Numeric.publicKeyDataSize) + 2

    const buf = this.newSerialBuffer(dataLength)
    buf.pushArray(buf.textEncoder.encode(this.pubKeyDidSignDataPrefix))
    buf.pushArray(buf.textEncoder.encode(actionName))
    buf.pushPublicKey(pubKey)
    buf.pushUint16(nonce)

    // console.log({data: buf.array, dataUtf8: new TextDecoder().decode(buf.array)})

    const digest = secp256k1.hash().update(buf.array).digest()
    return digest
  }

  async clearPubKeyDID() {
    if (!this.didPubKey) {
      throw new Error('public key did is not configured')
    }

    const nonce = await this.getNonceForPubKeyDid()
    const digest = this.digestForPubKeyDIDClearSig(this.didPubKey, nonce)
    const signature = this.didOwnerPrivateKeyObj.sign(digest, false)

    console.log({nonce, digest, signature: signature.toString()})

    // [[eosio::action]]
    // void pkrevokedid( const public_key& pk, const signature& sig, const name& ram_payer );

    return await this.api.transact({
      actions: [{
        account: this.registryContract,
        name: 'pkdidclear',
        authorization: [{
          actor: this.txfeePayerAccount,
          permission: 'active'
        }],
        data: {
          pk: this.didPubKey,
          sig: signature.toString()
        }
      }]
    }, {
      blocksBehind: 3,
      expireSeconds: 30
    })
  }

  async setAttributeAccountDID(key: string, value: string) {

    if (!this.didAccount) {
      throw new Error('account did is not configured')
    }

    // [[eosio::action]]
    // void accsetattr( const name& account, const string& key, const string& value );

    return await this.api.transact({
      actions: [{
        account: this.registryContract,
        name: 'accsetattr',
        authorization: [{
          actor: this.didAccount,
          permission: 'active'
        }],
        data: {
          account: this.didAccount,
          key,
          value
        }
      }]
    }, {
      blocksBehind: 3,
      expireSeconds: 30
    })
  }

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
