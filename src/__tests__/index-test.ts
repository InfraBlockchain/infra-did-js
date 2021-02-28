import InfraDID from '../index'

describe('InfraDID', () => {

  describe('DID creation', () => {
    it('should create pubKey DID (secp256k1)', () => {
      const networkId = 'kr01'
      const pubKeyDID = InfraDID.createPubKeyDIDsecp256k1(networkId)
      console.log({pubKeyDID})

      expect(pubKeyDID).toBeDefined()
      expect(pubKeyDID.did.startsWith(`did:infra:${networkId}:${pubKeyDID.publicKey}`)).toBeTruthy()
      expect(pubKeyDID.publicKey.startsWith('PUB_K1_')).toBeTruthy()
      expect(pubKeyDID.privateKey.startsWith('PVT_K1_')).toBeTruthy()
    })
  })

})
