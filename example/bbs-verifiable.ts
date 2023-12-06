import { BBSPlusPresentation, InfraSS58, Schema, VerifiableCredential, VerifiablePresentation } from "../src/infra-ss58/index";

function sleep(ms: number) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

let infraApi: InfraSS58;

async function main() {
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

    const vcId = 'did:infra:space:15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5';

    const txfeePayerAccountKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', 'sr25519');
    const edKeyPair = await InfraSS58.getKeyringPairFromUri('//Alice', 'ed25519');
    const networkId = "01";
    const confBlockchainNetwork = {
        networkId,
        address: 'ws://localhost:9901',
        txfeePayerAccountKeyPair,
    };
    const conf = {
        ...confBlockchainNetwork,
        did: 'did:infra:space:15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5',
        keyPair: edKeyPair,
        controllerDID: 'did:infra:space:15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5',
        controllerKeyPair: edKeyPair,
    };
    try {
        infraApi = await InfraSS58.createAsync(conf);

        await infraApi.didModule.registerOnChain();
        sleep(20000);

        const issuerBBSSigSet = await InfraSS58.BBSPlus_createNewSigSet(conf.did);
        await infraApi.bbsModule.addPublicKey(issuerBBSSigSet.publicKey);
        sleep(20000);

        let schema = new Schema('space');
        schema = await schema.setJSONSchema(someJSONSchema)

        const vc = new VerifiableCredential(vcId);
        vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
        vc.addContext('https://www.w3.org/2018/credentials/v1');
        vc.addContext('https://schema.org');
        vc.addType('VerifiableCredential');
        vc.addType('VaccinationCredential');
        vc.setSubject({ id: conf.did, alumniOf: 'Example University', email: 'test@test.com' });
        vc.setIssuer(conf.did);

        const bbsPlusPresentation = new BBSPlusPresentation();

        const { type } = issuerBBSSigSet.keyPair;
        const issuerKeyDoc = infraApi.getKeyDoc(`${conf.did}#keys-4`, conf.did, type, issuerBBSSigSet.keyPair);
        const issuedVC = await bbsPlusPresentation.issueCredential(issuerKeyDoc, vc.toJSON());

        const idx = await bbsPlusPresentation.addCredentialToPresent(issuedVC, { resolver: infraApi.Resolver });
        await bbsPlusPresentation.addCredentialSubjectAttributeToReveal(idx, ['alumniOf']);

        const presentation = await bbsPlusPresentation.createPresentation();
        console.log('presentation', JSON.stringify(presentation, null, 2));

        const vr = await bbsPlusPresentation.verifyPresentation(presentation, { resolver: infraApi.Resolver });
        console.log("verify result :::", vr);

        sleep(20000);
        await infraApi.didModule.unregisterOnChain();
    } catch (err) { 
        console.error(err);
    }
}

main();

