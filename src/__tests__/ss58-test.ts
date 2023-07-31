import { KeyObject } from 'crypto';
import { hexToU8a } from '@polkadot/util/hex/toU8a';
import { u8aToHex } from '@polkadot/util/u8a/toHex';
import { InfraSS58, DIDSet, HexString, IConfig_SS58, Schema, VerifiableCredential, VerifiablePresentation, BBSPlusPresentation, BBSPlus_SigSet, CryptoHelper, DerivedEd25519Key, DerivedEd25519KeySet, CRYPTO_BBS_INFO, KeyringPair, PublicJwk_ED } from '../index';


const vcId = 'did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U';
const vpId = 'http://example.edu/credentials/2803';
// const address = 'wss://infra2.infrablockchain.com'; 
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
    let edTest1: DIDSet;
    let contDIDSet: DIDSet;
    let edTest2: DIDSet;
    let config: IConfig_SS58;
    let txfeePayerAccountKeyPair: KeyringPair;
    describe('DID creation', () => {
        it('should create SR25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58.createNewSS58DIDSet('space')
                .then(srDIDSet => {
                    edTest1 = srDIDSet;
                    expect(srDIDSet.did).toBeDefined();
                })
        })
        it('should create ED25519 DID ', async () => {
            expect.assertions(1);
            return await InfraSS58.createNewSS58DIDSet('space')
                .then(edDIDSet => {
                    edTest2 = edDIDSet;
                    expect(edDIDSet.did).toBeDefined();
                })
        })
        it('get Error verify SS58 DID', () => {
            expect.assertions(1);
            expect(InfraSS58.validateInfraSS58DID('did:infra:02:isfaliedid').result).toBeFalsy();
        })
        it('verify SS58 DID', () => {
            expect.assertions(2);
            expect(InfraSS58.validateInfraSS58DID(edTest1.did).result).toBeTruthy();
            expect(InfraSS58.validateInfraSS58DID(edTest2.did).result).toBeTruthy();
        })
        it('convert SS58 DID to publicKey', () => {
            expect.assertions(2);
            const pk = InfraSS58.didToHexPk(edTest1.did)

            expect(edTest1.publicKey.toJSON()['Ed25519']).toEqual(pk)
            expect(InfraSS58.hexPkToDid(pk)).toEqual(edTest1.did)
        })
    })

    describe('DID onChain test', () => {
        beforeAll(async () => {
            jest.spyOn(console, 'warn').mockImplementation(() => {});
            txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', 'sr25519')
            edTest1 = await InfraSS58.createNewSS58DIDSet('space');
            contDIDSet = await InfraSS58.createNewSS58DIDSet('space');
            console.log('DID Set: ', edTest1)
            config = {
                address,
                networkId: 'space',

                did: edTest1.did,
                // seed or keyPair required
                // seed: srTest.seed,
                keyPair: edTest1.keyPair,
                // publicKey: srTest.publicKey,
                cryptoInfo: edTest1.cryptoInfo,
                verRels: edTest1.verRels,

                controllerDID: edTest1.did,
                controllerKeyPair: edTest1.keyPair,
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
                console.log('didDocument(offchain): ', JSON.stringify(didDocuments, null, 2));
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
                console.log('didDocument(onChain): ', JSON.stringify(didDocuments, null, 2));
                expect(didDocuments).toBeDefined();
            })
        })

        it('Add keys at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.addKeys(contDIDSet.didKey).then(async () =>
                await infraSS58.didModule.getDocument().then(doc => {
                    console.log('didDocument(onChain) after add keys: ', JSON.stringify(doc, null, 2));
                    expect(doc.verificationMethod.length).toBe(6);
                })
            )
        })

        it('Remove keys at onChain DID', async () => {
            expect.assertions(1);
            await infraSS58.didModule.removeKeys(2).then(async () =>
                await infraSS58.didModule.getDocument().then(doc => {
                    console.log('didDocument(onChain) after remove keys: ', JSON.stringify(doc, null, 2));

                    expect(doc.verificationMethod.length).toBe(3);
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
                        expect(doc.verificationMethod.length).toBe(3);
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

            txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', 'sr25519')
            edTest1 = await InfraSS58.createNewSS58DIDSet('space');
            config = {
                address,
                networkId: 'space',
                did: edTest1.did,
                seed: edTest1.seed,
                keyPair: edTest1.keyPair,
                txfeePayerAccountKeyPair,
                cryptoInfo: edTest1.cryptoInfo,
                verRels: edTest1.verRels,
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
            const sigSet = await InfraSS58.BBSPlus_createNewSigSet(edTest1.did);
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
                console.log('bbs+ didDocument(onChain): ', JSON.stringify(didDocuments, null, 2));
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

            txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', 'sr25519')
            edTest1 = await InfraSS58.createNewSS58DIDSet('space');
            edTest2 = await InfraSS58.createNewSS58DIDSet('space');
            config = {
                address,
                networkId: 'space',
                did: edTest1.did,
                seed: edTest1.seed,
                keyPair: edTest1.keyPair,
                txfeePayerAccountKeyPair,
                cryptoInfo: edTest1.cryptoInfo,
                verRels: edTest1.verRels,
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
            await infraSS58.trustModule.addIssuer(authorizerId, edTest2.did).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Get issuer', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.getIssuers(authorizerId, edTest2.did).then(issuer => {
                expect(issuer).toBeDefined();
            });
        })
        it('Remove issuer', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.removeIssuer(authorizerId, edTest2.did).then(res => {
                expect(res).toBeDefined();
            });
        })

        it('Add verifier', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.addVerifier(authorizerId, edTest2.did).then(res => {
                expect(res).toBeDefined();
            });
        })
        it('Get verifier', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.getVerifiers(authorizerId, edTest2.did).then(verifier => {
                expect(verifier).toBeDefined();
            });
        })
        it('Remove verifier', async () => {
            expect.assertions(1);
            await infraSS58.trustModule.removeVerifier(authorizerId, edTest2.did).then(res => {
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
    let txfeePayerAccountKeyPair: KeyringPair;
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
        txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', 'sr25519');
        issuer = await InfraSS58.createNewSS58DIDSet('space');
        holder = await InfraSS58.createNewSS58DIDSet('space');

        issuerApi = await InfraSS58.createAsync({
            address,
            networkId: 'space',
            did: issuer.did,
            seed: issuer.seed,
            txfeePayerAccountKeyPair,
            cryptoInfo: issuer.cryptoInfo,
            verRels: issuer.verRels,
        });
        holderApi = await InfraSS58.createAsync({
            address,
            networkId: 'space',
            did: holder.did,
            keyPair: holder.keyPair,
            txfeePayerAccountKeyPair,
            cryptoInfo: holder.cryptoInfo,
            verRels: holder.verRels,
        })

        await issuerApi.didModule.registerOnChain()
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
            await vc.sign(await issuerApi.didModule.getKeyDoc()).then(svc => {
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
                issuerBBSSigSet.keyPair.id = doc.verificationMethod.find(el => el.type === CRYPTO_BBS_INFO.BBSDockVerKeyName).id
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
    });


});

describe('CryptoHelper test', () => {
    let verifier: DIDSet;
    let holder: DIDSet;
    beforeAll(async () => {
        jest.spyOn(console, 'warn').mockImplementation(() => {});
        verifier = await InfraSS58.createNewSS58DIDSet('space');
        holder = await InfraSS58.createNewSS58DIDSet('space');
    })
    it('convert function test', async () => {
        const xPkU8a = CryptoHelper.edToX25519Pk(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), 'u8a');
        const xPkJwk = CryptoHelper.edToX25519Pk(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), 'jwk');
        const xPkKeyObject = CryptoHelper.edToX25519Pk(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), 'keyObject');
        expect(xPkU8a).toBeInstanceOf(Uint8Array);
        expect(xPkKeyObject).toBeInstanceOf(KeyObject);
        expect(xPkJwk).toHaveProperty('alg');
        expect(xPkJwk).toHaveProperty('crv');
        expect(xPkJwk).toHaveProperty('kty');
        expect(xPkJwk).toHaveProperty('x');

        const xSkU8a = CryptoHelper.edToX25519Sk(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), hexToU8a(verifier.seed), 'u8a');
        const xSkJwk = CryptoHelper.edToX25519Sk(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), hexToU8a(verifier.seed), 'jwk');
        const xSkKeyObject = CryptoHelper.edToX25519Sk(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), hexToU8a(verifier.seed), 'keyObject');
        expect(xSkU8a).toBeInstanceOf(Uint8Array);
        expect(xSkKeyObject).toBeInstanceOf(KeyObject);
        expect(xSkJwk).toHaveProperty('alg');
        expect(xSkJwk).toHaveProperty('crv');
        expect(xSkJwk).toHaveProperty('kty');
        expect(xSkJwk).toHaveProperty('x');
        expect(xSkJwk).toHaveProperty('d');

        const xKeypair = CryptoHelper.edToX25519KeyPair(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), hexToU8a(verifier.seed))
        expect(xKeypair.publicKey).toEqual(xPkU8a)
        expect(xKeypair.privateKey).toEqual(xSkU8a)
        expect(xKeypair.publicKeyJWK).toEqual(xPkJwk)
        expect(xKeypair.privateKeyJWK).toEqual(xSkJwk)

        const obj2JWK = CryptoHelper.keyObject2JWK(xPkKeyObject as KeyObject)
        expect(obj2JWK).toEqual(xPkJwk);
        const key2Jwk = CryptoHelper.key2JWK('X25519', xPkU8a as Uint8Array)
        expect(key2Jwk).toEqual(xPkJwk);
        const jwk2Key = CryptoHelper.jwk2Key(xPkJwk as PublicJwk_ED).publicKey
        expect(jwk2Key).toEqual(xPkU8a);
        const jwk2Obj = CryptoHelper.jwk2KeyObject(xPkJwk as PublicJwk_ED, 'public')
        expect(jwk2Obj).toEqual(xPkKeyObject);


    });
    it('create sharedKey test', async () => {
        const verifierX25519KeyPair = CryptoHelper.edToX25519KeyPair(hexToU8a(verifier.publicKey.toJSON()['Ed25519']), hexToU8a(verifier.seed));
        const holderX25519KeyPair = CryptoHelper.edToX25519KeyPair(hexToU8a(holder.publicKey.toJSON()['Ed25519']), hexToU8a(holder.seed));

        const { publicKey: epk, privateKey: esk } = CryptoHelper.generateX25519KeyPairObject();
        const verifierSecretUsingESK = CryptoHelper.x25519ToEcdhesKeypair(holderX25519KeyPair.publicKeyJWK, esk);
        const holderSecretUsingEPK = CryptoHelper.x25519ToEcdhesKeypair(epk, holderX25519KeyPair.privateKeyJWK);
        expect(verifierSecretUsingESK).toEqual(holderSecretUsingEPK);

        const verifierDIDSharedKey = CryptoHelper.x25519ToEcdhesKeypair(holderX25519KeyPair.publicKeyJWK, verifierX25519KeyPair.privateKeyJWK);
        const holderDIDSharedKey = CryptoHelper.x25519ToEcdhesKeypair(verifierX25519KeyPair.publicKeyJWK, holderX25519KeyPair.privateKeyJWK);
        expect(verifierDIDSharedKey).toEqual(holderDIDSharedKey);
    });

    it('slip-0010 derived key test(test vector 1)', async () => {
        //result set from https://github.com/satoshilabs/slips/blob/master/slip-0010.md
        // hex string added '0x', pk remove 00 pad
        const seed = '0x000102030405060708090a0b0c0d0e0f';

        const mk = await DerivedEd25519Key.getMasterKey(seed);
        expect(mk.path).toEqual('m');
        expect(u8aToHex(mk.chainCode)).toEqual('0x90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb');
        expect(u8aToHex(mk.sk)).toEqual('0x2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7');
        expect(u8aToHex(mk.pk)).toEqual('0xa4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed');

        const derivationpath = [DerivedEd25519Key.privdev + 0, 1, DerivedEd25519Key.privdev + 2, 2, 1000000000];
        let path = mk.path
        let k = mk.sk;
        let c = mk.chainCode;
        let pk = mk.pk;
        const keys: DerivedEd25519KeySet[] = []
        for (let i of derivationpath) {
            const dk = await DerivedEd25519Key.getDeriveKey(k, c, path, i);
            path = dk.path;
            k = dk.sk;
            c = dk.chainCode;
            pk = dk.pk;
            keys.push(dk);
        }
        expect(keys[0].path).toEqual('m/0h');
        expect(u8aToHex(keys[0].chainCode)).toEqual('0x8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69');
        expect(u8aToHex(keys[0].sk)).toEqual('0x68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3');
        expect(u8aToHex(keys[0].pk)).toEqual('0x8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c');

        expect(keys[1].path).toEqual('m/0h/1h');
        expect(u8aToHex(keys[1].chainCode)).toEqual('0xa320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14');
        expect(u8aToHex(keys[1].sk)).toEqual('0xb1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2');
        expect(u8aToHex(keys[1].pk)).toEqual('0x1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187');

        expect(keys[2].path).toEqual('m/0h/1h/2h');
        expect(u8aToHex(keys[2].chainCode)).toEqual('0x2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c');
        expect(u8aToHex(keys[2].sk)).toEqual('0x92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9');
        expect(u8aToHex(keys[2].pk)).toEqual('0xae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1');

        expect(keys[3].path).toEqual('m/0h/1h/2h/2h');
        expect(u8aToHex(keys[3].chainCode)).toEqual('0x8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc');
        expect(u8aToHex(keys[3].sk)).toEqual('0x30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662');
        expect(u8aToHex(keys[3].pk)).toEqual('0x8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c');

        expect(keys[4].path).toEqual('m/0h/1h/2h/2h/1000000000h');
        expect(u8aToHex(keys[4].chainCode)).toEqual('0x68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230');
        expect(u8aToHex(keys[4].sk)).toEqual('0x8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793');
        expect(u8aToHex(keys[4].pk)).toEqual('0x3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a');

    })
    it('slip-0010 derived key test(ss58)', async () => {
        //hardcode key -> it should same result any time
        // const publicKey = '0x1b8949a6533cf394ee1d6751f3d91acbf56fa803b60f134c868c31fd97ce7e3e';
        const seed = '0xdb78ac27eb5494268a490533db93f2bcdea7c822aed616e14713c74857debb85';

        const mk = await DerivedEd25519Key.getMasterKey(seed);
        expect(u8aToHex(mk.chainCode)).toEqual('0xb5129de87820f904b0419a4fcc9de733ceb80a6aed1cade08f03bf523d7cf8b2');
        expect(u8aToHex(mk.sk)).toEqual('0x88d7bfbff10d9b0a5022df66caf17d876de44672197befa903a0ccc3a9b6405c');
        expect(u8aToHex(mk.pk)).toEqual('0x28d551d4f419c516523cc345d5eb87259280b94defc1325de437a026f64d9173');

        const dk = await DerivedEd25519Key.getDeriveKey(mk.sk, mk.chainCode, mk.path, 0);
        expect(dk.path).toEqual('m/0h');
        expect(u8aToHex(dk.chainCode)).toEqual('0xac3cd30970141e7aaa27d38bd15c5c38e17d8d7f07c841f7ff15ce54a2134eef');
        expect(u8aToHex(dk.sk)).toEqual('0xe267aae616caa4591dde20526a5286f46bfb537775dbb44f6ab04f545180aabc');
        expect(u8aToHex(dk.pk)).toEqual('0xda2a05cf107afb4527b699fda0f5d79997eca42b90a4483ff36e0a11f70814dc');
    })
});