import { InfraSS58, CRYPTO_INFO, DIDSet, HexString, IConfig_SS58, Schema, KeyPair, VerifiableCredential, VerifiablePresentation, BBSPlusPresentation, BBSPlus_SigSet } from '../index';

const vcId = 'did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U';
const vpId = 'http://example.edu/credentials/2803';
// const address = 'wss://infra2.infrablockchain.com'; //'ws://localhost:9944';
const address = 'ws://localhost:9944';
const someJSONSchema = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    title: 'Schema Example',
    description: 'this is example',
    type: 'object',
    properties: {
        id: { type: 'string' },
        테스트: { type: 'string' },
        email: { type: 'string', format: 'email' },
        alumniOf: { type: 'string' },
    },
    required: ['email', 'alumniOf'],
    additionalProperties: false,
};
jest.setTimeout(300000)
describe('InfraSS58: DID', () => {
    let infraSS58: InfraSS58;
    let srTest: DIDSet;
    let contDIDSet: DIDSet;
    let edTest: DIDSet;
    let config: IConfig_SS58;
    let txfeePayerAccountKeyPair: KeyPair;
    describe.only('DID creation', () => {
        it('should create SR25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519)
                .then(srDIDSet => {
                    srTest = srDIDSet;
                    console.log({ srDIDSet })
                    expect(srDIDSet.did).toBeDefined();
                })
        })
        // it('should create Secp256k1 DID ', async () => {
        //     expect.assertions(1);
        //     return await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.Secp256k1)
        //         .then(secpDIDSet => {
        //             // console.log({ secpDIDSet })
        //             expect(secpDIDSet.did).toBeDefined();

        //         })
        // })
        it('should create ED25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.ED25519)
                .then(edDIDSet => {
                    edTest = edDIDSet;
                    // console.log({ edDIDSet })
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
        it('Extra: create and verify EdDSA alg JWT', async () => {

            expect.assertions(2);
            const senderApi = await InfraSS58.createAsync({
                address,
                networkId: 'space',
                did: srTest.did,
                keyPair: srTest.keyPair,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,
                txfeePayerAccountKeyPair,
            });
            const receiverApi = await InfraSS58.createAsync({
                address,
                networkId: 'space',
                did: edTest.did,
                keyPair: edTest.keyPair,
                cryptoInfo: edTest.cryptoInfo,
                verRels: edTest.verRels,
                txfeePayerAccountKeyPair,
            });

            const jwt = senderApi.didModule.createJWT({
                "iss": srTest.did,
                "iat": 1673231288,
                "exp": 1673234888,
                "aud": ["IWS.Cert"]
            });
            expect(jwt).toBeDefined();
            console.log({ jwt });
            const decodedJWT = await receiverApi.didModule.verifyAndDecodeJWT(jwt);
            console.log({ decodedJWT });
            expect(decodedJWT.verifyResult).toBeTruthy();
        })
    })

    describe('DID onChain test', () => {
        beforeAll(async () => {
            jest.spyOn(console, 'warn').mockImplementation(() => {});
            txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', CRYPTO_INFO.SR25519)
            srTest = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            contDIDSet = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            config = {
                address,
                networkId: 'space',

                did: srTest.did,
                // seed or keyPair required
                // seed: srTest.seed,
                keyPair: srTest.keyPair,
                // publicKey: srTest.publicKey,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,

                controllerDID: srTest.did,
                controllerKeyPair: srTest.keyPair,
                // controllerSeed: srTest.seed,

                txfeePayerAccountKeyPair,
                // txfeePayerAccountSeed: "someSeed",
            }
            infraSS58 = await InfraSS58.createAsync(config);


        })
        afterAll(async () => {
            await infraSS58.disconnect();
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
            jest.spyOn(console, 'warn').mockImplementation(() => {});

            txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', CRYPTO_INFO.SR25519)
            srTest = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            config = {
                address,
                networkId: 'space',
                did: srTest.did,
                seed: srTest.seed,
                keyPair: srTest.keyPair,
                txfeePayerAccountKeyPair,
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
            const sigSet = await InfraSS58.BBSPlus_createNewSigSet(srTest.did);
            console.log({ sigSet })
            return await infraSS58.bbsModule.addPublicKey(sigSet.publicKey).then(async () => {
                await infraSS58.bbsModule.getPublicKey(2).then(res => {
                    expect(res?.bytes).toEqual(sigSet.publicKey.bytes);
                });
            })
        })

        it('Get DID document(onChain)', async () => {
            expect.assertions(1);
            await infraSS58.didModule.getDocument().then(didDocuments => {
                console.log('didDocuments: ', didDocuments);
                expect(didDocuments).toBeDefined();
            })
        })
        it('Remove BBS+ publicKey', async () => {
            expect.assertions(1);
            await infraSS58.bbsModule.removePublicKey(2).then(async () => {
                await infraSS58.bbsModule.getPublicKey(2)
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

    describe('Trusted Entity test', () => {
        let authorizerId: HexString;

        beforeAll(async () => {
            jest.spyOn(console, 'warn').mockImplementation(() => {});

            txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', CRYPTO_INFO.SR25519)
            srTest = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
            edTest = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.ED25519);
            config = {
                address,
                networkId: 'space',
                did: srTest.did,
                seed: srTest.seed,
                keyPair: srTest.keyPair,
                txfeePayerAccountKeyPair,
                cryptoInfo: srTest.cryptoInfo,
                verRels: srTest.verRels,
            }
            infraSS58 = await InfraSS58.createAsync(config);
            await infraSS58.didModule.registerOnChain();

            authorizerId = infraSS58.trustModule.createNewAuthorizerId();
            console.log({ authorizerId });
            // add owner did if want
            // infraSS58.trustModule.addPolicyOwner("some did");
        })
        afterAll(async () => {
            if (infraSS58.isConnected) {
                await infraSS58.didModule.unregisterOnChain();
                await infraSS58.disconnect();
            }
        })
        it('Add new authorizer ', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.registerAuthorizer(authorizerId).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Get authorizer', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.getAuthorizer(authorizerId).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Add issuer', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.addIssuer(authorizerId, edTest.did).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Get issuer', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.getIssuers(authorizerId, edTest.did).then(issuer => {
                expect(issuer).toBeDefined();
            });
        })
        it('Remove issuer', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.removeIssuer(authorizerId, edTest.did).then(res => {
                expect(res).toBeDefined();
            });
        })

        it('Add verifier', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.addVerifier(authorizerId, edTest.did).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Get verifier', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.getVerifiers(authorizerId, edTest.did).then(verifier => {
                expect(verifier).toBeDefined();
            });
        })
        it('Remove verifier', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.removeVerifier(authorizerId, edTest.did).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Remove authorizer ', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.unregisterAuthorizer(authorizerId).then(res => {
                expect(res).toBeDefined();
            });
        })
    })
})

describe('InfraSS58: Verifiable', () => {
    let txfeePayerAccountKeyPair: KeyPair;
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
    let bbsPlusPresentation: BBSPlusPresentation;
    let issuerBBSSigSet: BBSPlus_SigSet;
    beforeAll(async () => {
        jest.spyOn(console, 'warn').mockImplementation(() => {});

        txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', CRYPTO_INFO.SR25519);
        issuer = await InfraSS58.createNewSS58DIDSet('space', CRYPTO_INFO.SR25519);
        issuerApi = await InfraSS58.createAsync({
            address,
            networkId: 'space',
            did: issuer.did,
            seed: issuer.seed,
            txfeePayerAccountKeyPair,
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
            txfeePayerAccountKeyPair,
            cryptoInfo: holder.cryptoInfo,
            verRels: holder.verRels,
        })
        await holderApi.didModule.registerOnChain();
        revokeId = issuerApi.registryModule.getRevokeId(vcId);


    })

    afterAll(async () => {
        await holderApi.didModule.unregisterOnChain();
        await holderApi.disconnect();
        await issuerApi.registryModule.unregisterRegistry(registryId);
        await issuerApi.didModule.unregisterOnChain();
        await issuerApi.disconnect();
    })

    describe('schema test', () => {
        it('create schema', async () => {
            expect.assertions(1);
            schema = new Schema('space');
            schema = await schema.setJSONSchema(someJSONSchema)
            console.log('schema::', JSON.stringify(schema.toJSON(), null, 2));
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
                // console.log('validate schema::', res)
                expect(res.valid).toBeTruthy();
            })

        })

    })
    describe('VC test', () => {

        it('add new Registry ', async () => {
            expect.assertions(1);
            registryId = issuerApi.registryModule.createNewRegistryId();
            console.log({ registryId });
            // add owner did if want
            // issuerApi.revocationModule.addPolicyOwner("some did");
            await issuerApi.registryModule.registerRegistry(registryId).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('get Registry ', async () => {
            expect.assertions(1);
            await issuerApi.registryModule.getRegistry(registryId).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Create VC', async () => {
            expect.assertions(1);
            vc = new VerifiableCredential(vcId);
            // vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
            vc.addContext('https://www.w3.org/2018/credentials/v1');
            vc.addContext('https://schema.org');
            vc.addType('VerifiableCredential');
            vc.addType('VaccinationCredential');
            vc.setSchema(schema.id);
            vc.addSubject({ id: holder.did, 테스트: '123', alumniOf: 'Example University', email: 'test@test.com' });
            // console.log('default vc json', vc.toJSON());
            expect(vc.toJSON()).toBeDefined();
        })

        it('Issue(Sign) VC', async () => {
            expect.assertions(1);
            await vc.sign(issuerApi.didModule.getKeyDoc()).then(svc => {
                signedVC = svc;
                console.log('signed VC::: ', signedVC.toJSON());
                expect(signedVC.proof.verificationMethod).toBeDefined();
            })
        })

        it('Validate VC schema', async () => {
            expect.assertions(1);
            await signedVC.validateSchema(schema).then(res => {
                // console.log('validate vc schema result::', res);
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
            await issuerApi.registryModule.getRegistry(registryId).then(res => {
                expect(res).toBeDefined();
            })
            let isRevoked = await issuerApi.registryModule.getIsRevoked(registryId, revokeId);
            expect(isRevoked).toBeFalsy();
            await issuerApi.registryModule.revokeCredential(registryId, revokeId);
            isRevoked = await issuerApi.registryModule.getIsRevoked(registryId, revokeId);
            expect(isRevoked).toBeTruthy();
            await issuerApi.registryModule.unrevokeCredential(registryId, revokeId);
            isRevoked = await issuerApi.registryModule.getIsRevoked(registryId, revokeId);
            expect(isRevoked).toBeFalsy();
        })
    })

    describe('VP test', () => {
        //TODO 테스트 수정 필요. Verifier 가 challange 생성해서 holder가 그걸로 생성하는 거임. 순서에 맞게 수정 필요.
        const domain = 'example domain';

        it('Create VP', async () => {
            expect.assertions(1);
            vp = new VerifiablePresentation(vpId);
            vp.addContext('https://www.w3.org/2018/credentials/examples/v1');
            vp.addType('CredentialManagerPresentation');
            vp.setHolder(holderApi.didModule.did);
            vp.addCredential(vc);
            expect(vp.toJSON()).toBeDefined();
        })

        it('Sign VP', async () => {
            expect.assertions(1);
            await vp.sign(holderApi, issuerApi.getChallenge(), domain)
                .then(svp => {
                    signedVP = svp;
                    console.log('signed VP::: ', JSON.stringify(signedVP.toJSON(), null, 2));
                    expect(signedVP).toBeDefined();
                })
        })

        it('Verify VP', async () => {
            expect.assertions(1);
            await signedVP.verify(issuerApi, issuerApi.getChallenge(), domain)
                .then(res => {
                    console.log('verified VP:::', JSON.stringify(res, null, 2));
                    expect(res.verified).toBeTruthy();
                })
        })


    })

    describe('BBS+ VP test', () => {
        beforeAll(async () => {
            //add bbs+ pubKey
            issuerBBSSigSet = await InfraSS58.BBSPlus_createNewSigSet(issuer.did);
            await issuerApi.bbsModule.addPublicKey(issuerBBSSigSet.publicKey);
            await issuerApi.didModule.getDocument().then(doc => {
                issuerBBSSigSet.keyPair.id = doc.verificationMethod[1].id
            });
            //set schema
            schema = new Schema('space');
            schema = await schema.setJSONSchema(someJSONSchema)
            // create credential
            vc = new VerifiableCredential(vcId);
            vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
            vc.addContext('https://www.w3.org/2018/credentials/v1');
            vc.addContext('https://schema.org');
            vc.addType('VerifiableCredential');
            vc.addType('VaccinationCredential');
            vc.setSchema(schema.toBBSSchema());
            vc.setSubject({ id: holder.did, alumniOf: 'Example University', email: 'test@test.com' });
            vc.setIssuer(issuer.did);

        })
        it('expect to reveal specified attributes', async () => {
            expect.assertions(3)

            bbsPlusPresentation = new BBSPlusPresentation();

            // Issue BBSPlus Credential
            const { id, type } = issuerBBSSigSet.keyPair;
            const issuerKeyDoc = issuerApi.getKeyDoc(id, issuer.did, type, issuerBBSSigSet.keyPair);
            const issuedVC = await bbsPlusPresentation.issueCredential(issuerKeyDoc, vc.toJSON());

            // Add Presentation and reveal Attribute
            const idx = await bbsPlusPresentation.addCredentialToPresent(issuedVC, { resolver: issuerApi.Resolver });
            await bbsPlusPresentation.addCredentialSubjectAttributeToReveal(idx, ['alumniOf']);

            // Issue BBSPlus Presentation
            const presentation = await bbsPlusPresentation.createPresentation();
            console.log('presentation', JSON.stringify(presentation, null, 2));

            expect(presentation.spec.credentials[0].revealedAttributes).toHaveProperty('credentialSubject');
            expect(presentation.spec.credentials[0].revealedAttributes.credentialSubject).toHaveProperty('alumniOf', 'Example University');

            // Verify Presentation
            const vr = await bbsPlusPresentation.verifyPresentation(presentation, { resolver: issuerApi.Resolver });
            console.log("verify result :::", vr);
            expect(vr.verified).toBeTruthy();
        })
    })

})