import InfraSS58DID, { CRYPTO_TYPE, IConfig } from '../infra-SS58'



describe('InfraSS58DID', () => {
    let testSet;
    // let config: IConfig;
    // let infraDID;

    beforeAll(async () => {
        // config = {
        //     did: testSet.did,
        //     address: 'ws://localhost:9944',
        // }
        // console.log(testSet);
        // infraDID = new InfraSS58DID(config);
    })

    describe('DID creation', () => {
        it('test', () => {
            expect(true).toEqual(true)
        })
        it('should create pubKey DID (sr25519)', async () => {
            testSet = await InfraSS58DID.createNewSS58DIDSet(CRYPTO_TYPE.SR25519)
            expect(InfraSS58DID.validateInfraSS58DID(testSet.did)).toEqual(true)
        })
    })

})