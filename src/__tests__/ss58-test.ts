import InfraSS58DID, { CRYPTO_INFO } from '../infra-ss58'
import VerifiableCredential from '../infra-ss58-vc';
import Schema from '../infra-ss58-vc/schema';
const failDID = "did:infra:space:thisisinvalidformofss58did"
const vcId = 'http://example.vc/credentials/123532';
const address = 'ws://localhost:9944';
jest.setTimeout(10000)
describe('InfraSS58DID', () => {
    let infraDID: InfraSS58DID;
    let srTest;
    let newDIDSet;
    let edTest;
    let config;
    let aliceAccount;
    describe.skip('DID creation', () => {
        it('should create SR25519 DID ', async () => {
            return await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519)
                .then(res => {
                    srTest = res;
                    expect(res.did).toBeDefined();
                })
        })
        it('should create ED25519 DID ', async () => {
            return await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.ED25519)
                .then(didSet => {
                    edTest = didSet;
                    console.log({ didSet })
                    expect(didSet.did).toBeDefined();
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

    describe.skip('DID onChain test', () => {
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

    describe.skip('BBS+ test', () => {
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

    describe('vc test', () => {
        let schema: Schema;
        let vc;
        let signedVC;
        let holder;
        let issuer;
        let holderApi;
        let issuerApi;
        beforeAll(async () => {
            aliceAccount = await InfraSS58DID.getKeyPairFromUri('//Alice', CRYPTO_INFO.SR25519);
            holder = await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            issuer = await InfraSS58DID.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            holderApi = await InfraSS58DID.createAsync({
                address,
                networkId: 'space',
                did: holder.did,
                seed: holder.seed,
                txfeePayerAccountKeyPair: aliceAccount,
                cryptoInfo: holder.cryptoInfo,
                verRels: holder.verRels,
            })
            await holderApi.registerOnChain();
            await holderApi.disconnect();

            issuerApi = await InfraSS58DID.createAsync({
                address,
                networkId: 'space',
                did: issuer.did,
                seed: issuer.seed,
                txfeePayerAccountKeyPair: aliceAccount,
                cryptoInfo: issuer.cryptoInfo,
                verRels: issuer.verRels,
            });
            await issuerApi.registerOnChain()
        })
        afterAll(async () => {
            await issuerApi.disconnect();
        })
        it('create schema', async () => {
            expect.assertions(1);
            let schema = new Schema();
            const someJSONSchema = {
                $schema: 'http://json-schema.org/draft-07/schema#',
                description: 'Dock Schema Example',
                type: 'object',
                properties: {
                    id: { type: 'string' },
                    petid: { type: 'string' },
                    emailAddress: { type: 'string', format: 'email' },
                    alumniOf: { type: 'string' },
                },
                required: ['emailAddress', 'alumniOf'],
                additionalProperties: false,
            };
            await schema.setJSONSchema(someJSONSchema).then(res => {

                schema = res;
                expect(schema.toJSON()).toBeDefined();
            })

        })
        it('write schema on chain', async () => {
            expect.assertions(2);

            await schema.writeToChain(issuerApi).then(res => {
                expect(res).toBeDefined()
            });
        })

        it('create vc', async () => {
            vc = new VerifiableCredential(vcId);
            vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
            vc.addContext('https://www.w3.org/2018/credentials/v1');
            vc.addType('VerifiableCredential');
            vc.addType('VaccinationCredential');
            vc.addSubject({ id: holder.did, alumniOf: 'Example University' });
            vc.setIssuanceDate('2021-04-02T10:11:41.000Z');
            expect(vc.toJSON()).toBeDefined();
        })

        it('sign vc', async () =>
            await vc.sign({
                id: `${edTest.did}#keys-1`,
                controller: edTest.did,
                type: edTest.cryptoInfo.KEY_TYPE,
                keypair: edTest.keyPair,
            }).then(svc => {
                signedVC = svc;
                console.log('signed::: ', signedVC.toJSON());
                expect(signedVC.proof.verificationMethod).toBeDefined();
            })
        )
        it('verify vc', async () => {
            await signedVC.verify({
                resolver: infraDID.Resolver,
                compactProof: true,
                forceRevocationCheck: true,
                // revocationApi: { dock },
            }).then(res => {
                console.log('verified:::', JSON.stringify(res, null, 2));
                expect(res.verified).toBeTruthy();
            })
        })
    })
})