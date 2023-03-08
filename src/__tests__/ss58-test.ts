import InfraSS58, { CRYPTO_INFO, DIDSet, HexString, IConfig_SS58, Schema, KeyPair, VerifiableCredential, VerifiablePresentation } from '../infra-ss58'

const vcId = 'http://example.vc/credentials/123532';
const vpId = 'http://example.edu/credentials/2803';
const address = 'ws://localhost:9944';
jest.setTimeout(10000)
describe('InfraSS58: DID', () => {
    let infraSS58: InfraSS58;
    let srTest: DIDSet;
    let contDIDSet: DIDSet;
    let edTest: DIDSet;
    let config: IConfig_SS58;
    let aliceAccount: KeyPair;
    describe('DID creation', () => {
        it('should create SR25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519)
                .then(srDIDSet => {
                    srTest = srDIDSet;
                    console.log({ srDIDSet })
                    expect(srDIDSet.did).toBeDefined();
                })
        })
        it('should create Secp256k1 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.Secp256k1)
                .then(secpDIDSet => {
                    console.log({ secpDIDSet })
                    expect(secpDIDSet.did).toBeDefined();

                })
        })
        it('should create ED25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.ED25519)
                .then(edDIDSet => {
                    edTest = edDIDSet;
                    console.log({ edDIDSet })
                    expect(edDIDSet.did).toBeDefined();
                })
        })
        it('get Error verify SS58 DID', () => {
            expect.assertions(1);
            expect(InfraSS58.validateInfraSS58DID('did:infra:02:isfaliedid').result).toBeFalsy();
        })
        it('verify SS58 DID', () => {
            expect.assertions(2);
            expect(InfraSS58.validateInfraSS58DID(srTest.did).result).toBeTruthy();
            expect(InfraSS58.validateInfraSS58DID(edTest.did).result).toBeTruthy();

        })
    })
    describe('DID onChain test', () => {
        beforeAll(async () => {
            aliceAccount = await InfraSS58.getKeyringPairFromUri('//Alice', CRYPTO_INFO.SR25519)
            srTest = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            contDIDSet = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.Secp256k1);
            config = {
                address,
                networkId: 'space',

                did: srTest.did,
                // seed or keyPair required
                seed: srTest.seed,
                keyPair: srTest.keyPair,
                // publicKey: srTest.publicKey,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,

                controllerDID: srTest.did,
                controllerKeyPair: srTest.keyPair,
                // controllerSeed: srTest.seed,

                txfeePayerAccountKeyPair: aliceAccount,
                // txfeePayerAccountSeed: "someSeed",
            }
            infraSS58 = await InfraSS58.createAsync(config);

        })
        afterAll(async () => {
            if (infraSS58.isConnected) await infraSS58.disconnect();
        })

        it('create SS58 DID instance', () => {
            expect.assertions(2);
            expect(infraSS58).toBeDefined();
            expect(infraSS58.isConnected).toBe(true);
        })

        it('get Error to remove not registered DID on chain', async () => {
            expect.assertions(1);
            await infraSS58.didModule.unregisterOnChain().catch(e => {
                expect(e).toBeDefined()
            })
        })
        it('Get DID document(not register)', async () => {
            expect.assertions(1);
            await infraSS58.didModule.getDocument().then(didDocuments => {
                console.log('default didDocuments: ', didDocuments);
                expect(didDocuments).toBeDefined();
            })
        })
        it('Register DID on chain', async () => {
            expect.assertions(1);
            await infraSS58.didModule.registerOnChain().then(res => {
                expect(res).toBeDefined();
            })
        })

        it('Get DID document(onChain)', async () => {
            expect.assertions(1);
            await infraSS58.didModule.getDocument().then(didDocuments => {
                console.log('didDocuments: ', didDocuments);
                expect(didDocuments).toBeDefined();
            })
        })

        it('Add keys at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.addKeys(contDIDSet.didKey).then(async () =>
                await infraSS58.didModule.getDocument().then(doc => {
                    expect(doc.verificationMethod.length).toBe(2);
                })
            )
        })

        it('Remove keys at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.removeKeys(2).then(async () =>
                await infraSS58.didModule.getDocument().then(doc => {
                    expect(doc.verificationMethod.length).toBe(1);
                })
            )
        })
        it('Add Controller DID at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.addControllers(contDIDSet.did).then(async () =>
                await infraSS58.didModule.isController(contDIDSet.did).then(res => {
                    expect(res).toBeTruthy();
                })
            )
        })

        it('Remove Controller DID at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.removeControllers(contDIDSet.did).then(async () =>
                await infraSS58.didModule.isController(contDIDSet.did).then(res => {
                    expect(res).toBeFalsy();
                })
            )
        })
        it('Add Service Endpoint at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.addServiceEndpoint(['https://foo.example.com']).then(async () =>
                await infraSS58.didModule.getServiceEndpoint().then(res => {
                    expect(res).toBeDefined();
                })
            )
        })
        it('Remove Service Endpoint at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.removeServiceEndpoint().then(async () =>
                await infraSS58.didModule.getServiceEndpoint().catch(e => {
                    expect(e).toBeDefined();
                })
            )
        })
        it('set attest Claim at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.setClaim(100,
                'https://rdf.dock.io/alpha/2021#attestsDocumentContent')
                .then(async () =>
                    await infraSS58.didModule.getDocument().then(doc => {
                        expect(doc.verificationMethod.length).toBe(1);
                    })
                )
        })
        it('Get Error to set attest Claim at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.setClaim(2,
                'http://www.w3.org/1999/02/22-rdf-syntax-ns#Property').catch(e => {
                    expect(e).toBeDefined();
                })
        })
        it('Remove DID on chain', async () => {
            expect.assertions(1);
            await infraSS58.didModule.unregisterOnChain().then(res => {
                expect(res).toBeDefined();
            })
        })
    })

    describe('BBS+ test', () => {
        beforeAll(async () => {
            aliceAccount = await InfraSS58.getKeyringPairFromUri('//Alice', CRYPTO_INFO.SR25519)
            srTest = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            config = {
                address,
                networkId: 'space',
                did: srTest.did,
                seed: srTest.seed,
                keyPair: srTest.keyPair,
                txfeePayerAccountKeyPair: aliceAccount,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,
            }
            infraSS58 = await InfraSS58.createAsync(config);
            await infraSS58.didModule.registerOnChain();

        })
        afterAll(async () => {
            if (infraSS58.isConnected) {
                await infraSS58.didModule.unregisterOnChain();
                await infraSS58.disconnect();
            }
        })
        it('Add BBS+ params', async () => {
            expect.assertions(1);
            const sigParam = InfraSS58.BBSPlus_createSigParamsWithLabel(10, 'test-param-label');
            return await infraSS58.bbsModule.addParams(sigParam).then(async () => {
                await infraSS58.bbsModule.getLastParamsWritten().then(res => {
                    expect(res).toBeDefined();
                });
            })
        })

        it('Get BBS+ params', async () => {
            expect.assertions(1);
            await infraSS58.bbsModule.getParams(1).then(async res1 => {
                await infraSS58.bbsModule.getLastParamsWritten().then(res2 => {
                    expect(res1).toEqual(res2)
                })
            })
        })

        it('Add BBS+ publicKey', async () => {
            expect.assertions(1);
            const sigSet = InfraSS58.BBSPlus_createNewSigSet(10);
            console.log({ sigSet })
            return await infraSS58.bbsModule.addPublicKey(sigSet.publicKey).then(async () => {
                await infraSS58.bbsModule.getPublicKey(2).then(res => {
                    expect(res?.bytes).toEqual(sigSet.publicKey.bytes);
                });
            })
        })

        it('Add BBS+ publicKey by did', async () => {
            expect.assertions(1);
            const testSigSet = await infraSS58.bbsModule.createNewSigSet(1);
            return await infraSS58.bbsModule.addPublicKey(testSigSet.publicKey).then(async () => {
                await infraSS58.bbsModule.getPublicKey(3).then(res => {
                    expect(res?.bytes).toEqual(testSigSet.publicKey.bytes);
                });
            })
        })

        it('Remove BBS+ publicKey', async () => {
            expect.assertions(1);
            await infraSS58.bbsModule.removePublicKey(3).then(async () => {
                await infraSS58.bbsModule.getPublicKey(3)
                    .then(res => { expect(res).toBeNull() })
            })
        })

        it('Remove BBS+ params', async () => {
            expect.assertions(1);
            await infraSS58.bbsModule.removeParams(1).then(async () => {
                await infraSS58.bbsModule.getParams(1).then(res => {
                    expect(res).toBeNull()
                })
            })
        })
    })

})

describe('InfraSS58: Verifiable', () => {
    let aliceAccount: KeyPair;
    let schema: Schema;
    let vc: VerifiableCredential;
    let signedVC: VerifiableCredential;
    let vp: VerifiablePresentation;
    let signedVP: VerifiablePresentation;
    let holder: DIDSet;
    let issuer: DIDSet;
    let holderApi: InfraSS58;
    let issuerApi: InfraSS58;
    let registryId: HexString;
    let revokeId: HexString;
    beforeAll(async () => {
        aliceAccount = await InfraSS58.getKeyringPairFromUri('//Alice', CRYPTO_INFO.SR25519);
        issuer = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.Secp256k1);
        issuerApi = await InfraSS58.createAsync({
            address,
            networkId: 'space',
            did: issuer.did,
            seed: issuer.seed,
            txfeePayerAccountKeyPair: aliceAccount,
            cryptoInfo: issuer.cryptoInfo,
            verRels: issuer.verRels,
        });
        await issuerApi.didModule.registerOnChain()
        holder = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.ED25519);
        holderApi = await InfraSS58.createAsync({
            address,
            networkId: 'space',
            did: holder.did,
            keyPair: holder.keyPair,
            txfeePayerAccountKeyPair: aliceAccount,
            cryptoInfo: holder.cryptoInfo,
            verRels: holder.verRels,
        })
        await holderApi.didModule.registerOnChain();
        revokeId = issuerApi.revocationModule.getRevokeId(vcId);
    })

    afterAll(async () => {
        await holderApi.disconnect();
        await issuerApi.revocationModule.removeRegistryWithOneOfPolicy(registryId);
        await issuerApi.disconnect();
    })

    describe('schema test', () => {

        it('create schema', async () => {
            expect.assertions(1);
            schema = new Schema('space');
            const someJSONSchema = {
                $schema: 'http://json-schema.org/draft-07/schema#',
                description: 'Schema Example',
                type: 'object',
                properties: {
                    id: { type: 'string' },
                    email: { type: 'string', format: 'email' },
                    alumniOf: { type: 'string' },
                },
                required: ['email', 'alumniOf'],
                additionalProperties: false,
            };
            schema = await schema.setJSONSchema(someJSONSchema)
            console.log('default schema::', JSON.stringify(schema.toJSON(), null, 2));
            expect(schema.toJSON()).toBeDefined();
        })

        it('Write schema on chain by Api', async () => {
            expect.assertions(1);
            await issuerApi.blobModule.writeSchemaOnChainByBlob(schema.toBlob())
                .then(res => {
                    expect(res).toBeDefined()
                });
        })

        it('get Error write schema on chain by Schema', async () => {
            expect.assertions(1);
            await schema.writeToChain(issuerApi)
                .catch(e => {
                    expect(e).toBeDefined()
                });
        })

        it('get schema', async () => {
            expect.assertions(1);
            const fromApi = await issuerApi.blobModule.getSchema(schema.id);
            await Schema.get(schema.id, issuerApi)
                .then(res => {
                    console.log('get schema::', JSON.stringify(res, null, 2))
                    expect(res?.id).toEqual(fromApi?.id);
                })
        })

        it('Validate JSON schema', async () => {
            expect.assertions(1);
            await Schema.validateSchema(schema.schema).then(res => {
                console.log('validate schema::', res)
                expect(res.valid).toBeTruthy();
            })

        })

    })
    describe('VC test', () => {

        it('add new Registry ', async () => {
            expect.assertions(1);
            registryId = issuerApi.revocationModule.createNewRegistryId();
            console.log({ registryId });
            // add owner did if want
            // issuerApi.revocationModule.addPolicyOwner("some did");
            await issuerApi.revocationModule.newRegistry(registryId).then(res => {
                expect(res).toBeDefined();
            });
        })

        it('Create VC', async () => {
            expect.assertions(1);
            vc = new VerifiableCredential(vcId);
            vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
            vc.addContext('https://www.w3.org/2018/credentials/v1');
            vc.addContext('https://schema.org');
            vc.addType('VerifiableCredential');
            vc.addType('VaccinationCredential');
            vc.setSchema(schema.id, 'JsonSchemaValidator2018');
            vc.addSubject({ id: holder.did, alumniOf: 'Example University', email: 'test@test.com' });
            vc.setIssuanceDate('2021-04-02T10:11:41.000Z');
            console.log('default vc', vc.toJSON());
            expect(vc.toJSON()).toBeDefined();
        })

        it('Issue(Sign) VC', async () => {
            expect.assertions(1);
            await vc.sign(issuerApi.getKeyDoc()).then(svc => {
                signedVC = svc;
                console.log('signed VC::: ', signedVC.toJSON());
                expect(signedVC.proof.verificationMethod).toBeDefined();
            })
        })

        it('Validate VC schema', async () => {
            expect.assertions(1);
            await signedVC.validateSchema(schema).then(res => {
                console.log('validate vc schema result::', res);
                expect(res).toBeTruthy();
            })
        })

        it('Verify VC', async () => {
            expect.assertions(1);
            await signedVC.verify(issuerApi).then(res => {
                console.log('verified VC:::', JSON.stringify(res, null, 2));
                expect(res.verified).toBeTruthy();
            })
        })

        it('Revoke VC', async () => {
            expect.assertions(4);
            await issuerApi.revocationModule.getRevocationRegistry(registryId).then(res => {
                expect(res).toBeDefined();
            })
            let isRevoked = await issuerApi.revocationModule.getIsRevoked(registryId, revokeId);
            expect(isRevoked).toBeFalsy();
            await issuerApi.revocationModule.revokeCredentialWithOneOfPolicy(registryId, revokeId);
            isRevoked = await issuerApi.revocationModule.getIsRevoked(registryId, revokeId);
            expect(isRevoked).toBeTruthy();
            await issuerApi.revocationModule.unrevokeCredentialWithOneOfPolicy(registryId, revokeId);
            isRevoked = await issuerApi.revocationModule.getIsRevoked(registryId, revokeId);
            expect(isRevoked).toBeFalsy();
        })
    })

    describe('VP test', () => {
        const domain = 'example domain';

        it('Create VP', async () => {
            expect.assertions(1);
            vp = new VerifiablePresentation(vpId);
            vp.addContext('https://www.w3.org/2018/credentials/examples/v1');
            vp.addType('CredentialManagerPresentation');
            vp.setHolder(holderApi.didModule.did);
            vp.addCredential(vc);
            console.log('default vp', vp.toJSON());
            expect(vp.toJSON()).toBeDefined();
        })

        it('Sign VP', async () => {
            expect.assertions(1);
            await vp.sign(holderApi, domain)
                .then(svp => {
                    signedVP = svp;
                    console.log('signed VP::: ', signedVP.toJSON());
                    expect(signedVP).toBeDefined();
                })
        })

        it('Verify VP', async () => {
            expect.assertions(1);
            await signedVP.verify(issuerApi, holderApi.getChallenge(), domain)
                .then(res => {
                    console.log('verified VP:::', JSON.stringify(res, null, 2));
                    expect(res.verified).toBeTruthy();
                })
        })


    })

})