import InfraSS58DID, { CRYPTO_INFO, DIDSet, IConfig, PublicKey } from '../infra-SS58'
import { Keyring } from '@polkadot/api';
import { KeyringPair } from '@polkadot/keyring/types';
import { cryptoWaitReady, } from '@polkadot/util-crypto';


const failDID = "did:infra:02:thisisinvalidformofss58did"
const address = 'ws://localhost:9944';

describe('InfraSS58DID', () => {
    let srTest: DIDSet;
    let edTest: DIDSet;
    let infraDID: InfraSS58DID;
    let config: IConfig;
    let alice: KeyringPair;
    let newDIDSet: DIDSet;
    beforeAll(async () => {

    })

    describe('DID creation', () => {
        it('should create SS25519 DID ', async () => {
            return await InfraSS58DID.createNewSS58DIDSet(CRYPTO_INFO.SR25519)
                .then(res => {
                    srTest = res;
                    expect(res.did).toBeDefined();
                })
        })
        it('should create ED25519 DID ', async () => {
            return await InfraSS58DID.createNewSS58DIDSet(CRYPTO_INFO.ED25519)
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
            srTest = await InfraSS58DID.createNewSS58DIDSet(CRYPTO_INFO.SR25519);
            newDIDSet = await InfraSS58DID.createNewSS58DIDSet(CRYPTO_INFO.SR25519);
            config = {
                address,
                did: srTest.did,
                seed: srTest.seed,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,
            }
            infraDID = await InfraSS58DID.createAsync(config);
            await cryptoWaitReady();
            const keyringModule = new Keyring({ type: 'sr25519' });
            alice = keyringModule.addFromUri('//Alice');

        })
        afterAll(async () => {
            if (infraDID.isConnected) await infraDID.disconnect();
        })

        it('create SS58 DID instance', () => {
            expect(infraDID).toBeDefined();
            expect(infraDID.isConnected).toBe(true);
        })
        it('set / get Account', () => {
            infraDID.setAccount(alice)
            expect(infraDID.getAccount()).toEqual(alice)
        })
        it('get Error to remove not registered DID on chain', async () =>
            await infraDID.removeOnChain().catch(e => {
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
            await infraDID.addKeys([newDIDSet.didKey]).then(async () =>
                await infraDID.getDocument().then(doc => {
                    expect(doc.publicKey.length).toBe(2);
                })
            )
        )
        it('Remove keys at onChain DID', async () =>
            await infraDID.removeKeys(2).then(async () =>
                await infraDID.getDocument().then(doc => {
                    expect(doc.publicKey.length).toBe(1);
                })
            )
        )
        it('Add Controller DID at onChain DID', async () =>
            await infraDID.addController([newDIDSet.did]).then(async () =>
                await infraDID.isController(newDIDSet.did).then(res => {
                    expect(res).toBeTruthy();
                })
            )
        )
        it('Remove Controller DID at onChain DID', async () =>
            await infraDID.removeControllers([newDIDSet.did]).then(async () =>
                await infraDID.isController(newDIDSet.did).then(res => {
                    expect(res).toBeFalsy();
                })
            )
        )
        it('Add Service Endpoint at onChain DID', async () =>
            await infraDID.addServiceEndpoint().then(async () =>
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
            await infraDID.removeOnChain().then(res => {
                expect(res).toBeDefined();
            })
        )
    })

    describe('bbs+ test', () => {
        beforeAll(async () => {
            srTest = await InfraSS58DID.createNewSS58DIDSet(CRYPTO_INFO.SR25519);

            config = {
                address,
                did: srTest.did,
                seed: srTest.seed,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,
            }
            infraDID = await InfraSS58DID.createAsync(config);
            await cryptoWaitReady();
            const keyringModule = new Keyring({ type: 'sr25519' });
            alice = keyringModule.addFromUri('//Alice');
            infraDID.setAccount(alice);
            await infraDID.registerOnChain();

        })
        afterAll(async () => {
            if (infraDID.isConnected) await infraDID.disconnect();
        })
        it('Add bbs+ params', async () => {
            const sigParam = InfraSS58DID.BBSPlus_createSigParamsWithLabel(10, 'test-param-label');
            return await infraDID.BBSPlus_addParams(sigParam).then(async () => {
                await infraDID.BBSPlus_getLastParamsWritten().then(res => {
                    expect(res).toBeDefined();
                });
            })
        })

        it('Get bbs+ params', async () => {
            await infraDID.BBSPlus_getParams(1).then(async res1 => {
                await infraDID.BBSPlus_getLastParamsWritten().then(res2 => {
                    expect(res1).toEqual(res2)
                    // console.log('getParams:', res2)
                })
            })
        })


        it('Add bbs+ publicKey', async () => {
            const sigParam = InfraSS58DID.BBSPlus_createSigParamsWithLabel(10)
            const pk = InfraSS58DID.BBSPlus_createG1SigPublicKey(sigParam);
            return await infraDID.BBSPlus_addPublicKey(pk).then(async () => {
                await infraDID.BBSPlus_getPublicKey(2).then(res => {
                    expect(res?.bytes).toEqual(pk.bytes);
                });
            })
        })

        it('Add bbs+ publicKey by did', async () => {
            const sigParam = await infraDID.BBSPlus_createSigParamsByDID(1)
            const pk = InfraSS58DID.BBSPlus_createG1SigPublicKey(sigParam);
            return await infraDID.BBSPlus_addPublicKey(pk).then(async () => {
                await infraDID.BBSPlus_getPublicKey(3).then(res => {
                    expect(res?.bytes).toEqual(pk.bytes);
                });
            })
        })



        it('Remove bbs+ publicKey', async () => {
            return await infraDID.BBSPlus_removePublicKey(3).then(async () => {
                await infraDID.BBSPlus_getPublicKey(3).catch(e => {
                    expect(e).toBeDefined()
                })
            })
        })

        it('Remove bbs+ params', async () => {
            await infraDID.BBSPlus_removeParams(1).then(async () => {
                await infraDID.BBSPlus_getParams(1).catch(e => {
                    expect(e).toBeDefined()
                })
            })
        })

        it('Remove DID on chain', async () =>
            await infraDID.removeOnChain().then(res => {
                expect(res).toBeDefined();
            })
        )

    })
})