import InfraSS58DID, { CRYPTO_INFO, DIDSet, IConfig, Keyring, KeyringPair, cryptoWaitReady } from '../infra-SS58'

const failDID = "did:infra:02:thisisinvalidformofss58did"
const address = 'ws://localhost:9944';

describe('InfraSS58DID', () => {
    let srTest: DIDSet;
    let edTest: DIDSet;
    let infraDID: InfraSS58DID;
    let config: IConfig;
    let alice: KeyringPair;
    let newDIDSet: DIDSet;

    describe('DID creation', () => {
        it('should create SR25519 DID ', async () => {
            return await InfraSS58DID.createNewSS58DIDSet('02', CRYPTO_INFO.SR25519)
                .then(res => {
                    srTest = res;
                    expect(res.did).toBeDefined();
                })
        })
        it('should create ED25519 DID ', async () => {
            return await InfraSS58DID.createNewSS58DIDSet('02', CRYPTO_INFO.ED25519)
                .then(res => {
                    edTest = res;
                    expect(res.did).toBeDefined();
                })
        })
        it('get Error verify DID', () => {
            expect(() => InfraSS58DID.validateInfraSS58DID(failDID)).toThrow();
        })
        it('verify DID', () => {
            expect(InfraSS58DID.validateInfraSS58DID(srTest.did)).toBeTruthy();
            expect(InfraSS58DID.validateInfraSS58DID(edTest.did)).toBeTruthy();
        })
    })

    describe('DID onChain test', () => {
        beforeAll(async () => {
            await cryptoWaitReady();
            alice = (new Keyring({ type: 'sr25519' })).addFromUri('//Alice');
            srTest = await InfraSS58DID.createNewSS58DIDSet('02', CRYPTO_INFO.SR25519);
            newDIDSet = await InfraSS58DID.createNewSS58DIDSet('02', CRYPTO_INFO.SR25519);
            config = {
                address,
                networkId: '02',
                did: srTest.did,
                controllerDID: srTest.did,
                controllerKeyPair: srTest.keyPair,
                txfeePayerAccountKeyPair: alice,
                seed: srTest.seed,
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
        it('Register DID on chain', async () =>
            await infraDID.registerOnChain().then(res => {
                expect(res).toBeDefined()
            })
        )
        it('Get DID document', async () =>
            await infraDID.getDocument().then(res => {
                expect(res).toBeDefined();
            })
        )
        it('Add keys at onChain DID', async () =>
            await infraDID.addPublicKeyByDIDKeys(newDIDSet.didKey).then(async () =>
                await infraDID.getDocument().then(doc => {
                    expect(doc.publicKey.length).toBe(2);
                })
            )
        )
        it('Remove keys at onChain DID', async () =>
            await infraDID.removePublicKeys(2).then(async () =>
                await infraDID.getDocument().then(doc => {
                    expect(doc.publicKey.length).toBe(1);
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
                        expect(doc.publicKey.length).toBe(1);
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
            await cryptoWaitReady();
            const keyringModule = new Keyring({ type: 'sr25519' });
            alice = keyringModule.addFromUri('//Alice');

            srTest = await InfraSS58DID.createNewSS58DIDSet(
                '02', CRYPTO_INFO.SR25519);

            config = {
                networkId: '02',
                address,
                did: srTest.did,
                txfeePayerAccountKeyPair: alice,
                seed: srTest.seed,
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
            const testSet = InfraSS58DID.BBSPlus_createNewSigSet(10);
            return await infraDID.BBSPlus_addPublicKey(testSet.publicKey).then(async () => {
                await infraDID.BBSPlus_getPublicKey(2).then(res => {
                    expect(res?.bytes).toEqual(testSet.publicKey.bytes);
                });
            })
        })

        it('Add BBS+ publicKey by did', async () => {
            const testSet = await infraDID.BBSPlus_createNewSigSet(1);
            return await infraDID.BBSPlus_addPublicKey(testSet.publicKey).then(async () => {
                await infraDID.BBSPlus_getPublicKey(3).then(res => {
                    expect(res?.bytes).toEqual(testSet.publicKey.bytes);
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