import InfraSS58DID, { CRYPTO_INFO, DIDSet_SS58, IConfig_SS58, KeyringPair } from '../infra-SS58'

const failDID = "did:infra:space:thisisinvalidformofss58did"
const address = 'ws://localhost:9944';
jest.setTimeout(10000)
describe('InfraSS58DID', () => {
    let infraDID: InfraSS58DID;
    let srTest: DIDSet_SS58;
    let edTest: DIDSet_SS58;
    let config: IConfig_SS58;
    let aliceAccount: KeyringPair;
    let newDIDSet: DIDSet_SS58;

    describe('DID creation', () => {
        it('should create SR25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519)
                .then(didSet => {
                    srTest = didSet;
                    expect(didSet.did).toBeDefined();
                })
        })
        it('should create ED25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.ED25519)
                .then(didSet => {
                    edTest = didSet;
                    console.log({ didSet })
                    expect(didSet.did).toBeDefined();
                })
        })
        it('get failed verify DID', () => {
            expect.assertions(2);
            const valid = InfraSS58DID.validateInfraSS58DID(failDID)
            expect(valid.msg).toBeDefined();
            expect(valid.result).toBeFalsy();
        })
        it('verify DID', () => {
            expect.assertions(2);
            expect(InfraSS58DID.validateInfraSS58DID(srTest.did)).toBeTruthy();
            expect(InfraSS58DID.validateInfraSS58DID(edTest.did)).toBeTruthy();
        })
    })

    describe('DID onChain test', () => {
        beforeAll(async () => {
            aliceAccount = await InfraSS58DID.getKeyPairFromUri('//Alice', CRYPTO_INFO.SR25519)
            srTest = await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            newDIDSet = await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            config = {
                address,
                networkId: 'space',

                did: srTest.did,
                seed: srTest.seed,
                // mnemonic:srTest.mnemonic,

                controllerDID: srTest.did,
                controllerKeyPair: srTest.keyPair,
                // controllerSeed: srTest.seed,
                txfeePayerAccountKeyPair: aliceAccount,

                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,
            }
            infraDID = await InfraSS58DID.createAsync(config);

        })
        afterAll(async () => {
            if (infraDID.isConnected) await infraDID.disconnect();
        })

        it('create SS58 DID instance', () => {
            expect(infraDID).toBeDefined();
            expect(infraDID.isConnected).toBe(true);
        })

        it('get Error to remove not registered DID on chain', async () =>
            await infraDID.unregisterOnChain().catch(e => {
                expect(e).toBeDefined()
            })
        )
        it('Get DID document(not register)', async () =>
            await infraDID.getDocument().then(didDocuments => {
                console.log('default didDocuments: ', didDocuments);
                expect(didDocuments).toBeDefined();
            })
        )
        it('Register DID on chain', async () =>
            await infraDID.registerOnChain().then(res => {
                expect(res).toBeDefined();
            })
        )

        it('Get DID document(onChain)', async () =>
            await infraDID.getDocument().then(didDocuments => {
                console.log('didDocuments: ', didDocuments);
                expect(didDocuments).toBeDefined();
            })
        )
        it('Add keys at onChain DID', async () =>
            await infraDID.addKeys(newDIDSet.didKey).then(async () =>
                await infraDID.getDocument().then(doc => {
                    expect(doc.verificationMethod.length).toBe(2);
                })
            )
        )
        it('Remove keys at onChain DID', async () =>
            await infraDID.removeKeys(2).then(async () =>
                await infraDID.getDocument().then(doc => {
                    expect(doc.verificationMethod.length).toBe(1);
                })
            )
        )
        it('Add Controller DID at onChain DID', async () =>
            await infraDID.addControllers(newDIDSet.did).then(async () =>
                await infraDID.isController(newDIDSet.did).then(res => {
                    expect(res).toBeTruthy();
                })
            )
        )
        it('Remove Controller DID at onChain DID', async () =>
            await infraDID.removeControllers(newDIDSet.did).then(async () =>
                await infraDID.isController(newDIDSet.did).then(res => {
                    expect(res).toBeFalsy();
                })
            )
        )
        it('Add Service Endpoint at onChain DID', async () =>
            await infraDID.addServiceEndpoint(['https://foo.example.com']).then(async () =>
                await infraDID.getServiceEndpoint().then(res => {
                    expect(res).toBeDefined();
                })
            )
        )
        it('Remove Service Endpoint at onChain DID', async () =>
            await infraDID.removeServiceEndpoint().then(async () =>
                await infraDID.getServiceEndpoint().catch(e => {
                    expect(e).toBeDefined();
                })
            )
        )
        it('set attest Claim at onChain DID', async () =>
            await infraDID.setClaim(100,
                'https://rdf.dock.io/alpha/2021#attestsDocumentContent').then(async () =>
                    await infraDID.getDocument().then(doc => {
                        expect(doc.verificationMethod.length).toBe(1);
                    })
                )
        )
        it('Get Error to set attest Claim at onChain DID', async () =>
            await infraDID.setClaim(2,
                'http://www.w3.org/1999/02/22-rdf-syntax-ns#Property').catch(e => {
                    expect(e).toBeDefined();
                })
        )
        it('Remove DID on chain', async () =>
            await infraDID.unregisterOnChain().then(res => {
                expect(res).toBeDefined();
            })
        )
    })

    describe('BBS+ test', () => {
        beforeAll(async () => {
            aliceAccount = await InfraSS58DID.getKeyPairFromUri('//Alice', CRYPTO_INFO.SR25519)

            srTest = await InfraSS58DID.createNewSS58DIDSet(
                'space', CRYPTO_INFO.SR25519);
            config = {
                address,
                networkId: 'space',

                did: srTest.did,
                seed: srTest.seed,
                // mnemonic:srTest.mnemonic,
                txfeePayerAccountKeyPair: aliceAccount,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,
            }
            infraDID = await InfraSS58DID.createAsync(config);
            await infraDID.registerOnChain();

        })
        afterAll(async () => {
            if (infraDID.isConnected) {
                await infraDID.unregisterOnChain();
                await infraDID.disconnect();
            }
        })
        it('Add BBS+ params', async () => {
            const sigParam = InfraSS58DID.BBSPlus_createSigParamsWithLabel(10, 'test-param-label');
            return await infraDID.BBSPlus_addParams(sigParam).then(async () => {
                await infraDID.BBSPlus_getLastParamsWritten().then(res => {
                    expect(res).toBeDefined();
                });
            })
        })

        it('Get BBS+ params', async () => {
            await infraDID.BBSPlus_getParams(1).then(async res1 => {
                await infraDID.BBSPlus_getLastParamsWritten().then(res2 => {
                    expect(res1).toEqual(res2)
                })
            })
        })


        it('Add BBS+ publicKey', async () => {
            const sigSet = InfraSS58DID.BBSPlus_createNewSigSet(10);
            console.log({ sigSet })
            return await infraDID.BBSPlus_addPublicKey(sigSet.publicKey).then(async () => {
                await infraDID.BBSPlus_getPublicKey(2).then(res => {
                    expect(res?.bytes).toEqual(sigSet.publicKey.bytes);
                });
            })
        })

        it('Add BBS+ publicKey by did', async () => {
            const testSigSet = await infraDID.BBSPlus_createNewSigSet(1);
            return await infraDID.BBSPlus_addPublicKey(testSigSet.publicKey).then(async () => {
                await infraDID.BBSPlus_getPublicKey(3).then(res => {
                    expect(res?.bytes).toEqual(testSigSet.publicKey.bytes);
                });
            })
        })



        it('Remove BBS+ publicKey', async () => {
            return await infraDID.BBSPlus_removePublicKey(3).then(async () => {
                await infraDID.BBSPlus_getPublicKey(3).catch(e => {
                    expect(e).toBeDefined()
                })
            })
        })

        it('Remove BBS+ params', async () => {
            await infraDID.BBSPlus_removeParams(1).then(async () => {
                await infraDID.BBSPlus_getParams(1).catch(e => {
                    expect(e).toBeDefined()
                })
            })
        })
    })
})