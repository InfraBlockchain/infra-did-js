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
    const vpId = 'did:infra:space:15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp4';
    const domain = 'example domain';

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

    infraApi = await InfraSS58.createAsync(conf);

    await infraApi.didModule.registerOnChain();
    sleep(20000);

    let schema = new Schema('space');
    schema = await schema.setJSONSchema(someJSONSchema);
    console.log('schema::', JSON.stringify(schema.toJSON(), null, 2));

    await infraApi.blobModule.writeSchemaOnChainByBlob(schema.toBlob());
    sleep(20000);
    const schemaResponse = await Schema.get(schema.id, infraApi);
    console.log(JSON.stringify(schemaResponse, null, 2));
    const validResponse = await Schema.validateSchema(schema.schema);
    console.log(validResponse);

    const vc = new VerifiableCredential(vcId);
    vc.addContext('https://www.w3.org/2018/credentials/v1');
    vc.addContext('https://schema.org');
    vc.addType('VerifiableCredential');
    vc.addType('VaccinationCredential');
    vc.setSchema(schema.id);
    vc.addSubject({ id: conf.did, 테스트: '123', alumniOf: 'Example University', email: 'test@test.com' });

    const signedVC = await vc.sign(await infraApi.didModule.getKeyDoc());
    console.log(signedVC);
    const validVC = await signedVC.validateSchema(schema);
    console.log("validVC: ", validVC);
    const verifyVC = await signedVC.verify(infraApi);
    console.log("verifyVC: ", verifyVC);

    const vp = new VerifiablePresentation(vpId);
    vp.addContext('https://www.w3.org/2018/credentials/examples/v1');
    vp.addType('CredentialManagerPresentation');
    vp.setHolder(infraApi.didModule.did);
    vp.addCredential(vc);

    const signedVP = await vp.sign(infraApi, infraApi.getChallenge(), domain);
    const verifyVP = await signedVP.verify(infraApi, infraApi.getChallenge(), domain)
    console.log("verifyVP:", verifyVP)

    sleep(20000);
    await infraApi.didModule.unregisterOnChain();
}

main();

