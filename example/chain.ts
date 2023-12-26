import { InfraSS58 } from "../src/infra-ss58/index";

function sleep(ms: number) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

let infraApi: InfraSS58;

async function main() {
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

    const DIDSet = await InfraSS58.createNewSS58DIDSet(networkId)
    const DIDSet2 = await InfraSS58.createNewSS58DIDSet(networkId)

    await infraApi.didModule.registerOnChain();
    sleep(20000);
    await infraApi.didModule.addKeys(DIDSet.didKey);
    sleep(20000);
    await infraApi.didModule.removeKeys(2);
    sleep(20000);
    await infraApi.didModule.addControllers(DIDSet.did);
    sleep(20000);
    await infraApi.didModule.removeControllers(DIDSet.did);
    sleep(20000);
    await infraApi.didModule.addServiceEndpoint(['https://foo.example.com']);
    sleep(20000);
    await infraApi.didModule.removeServiceEndpoint();
    sleep(20000);

    const sigParam = InfraSS58.BBSPlus_createSigParamsWithLabel(10, 'test-param-label');
    await infraApi.bbsModule.addParams(sigParam, "test-param-label");
    sleep(20000);
    const param = await infraApi.bbsModule.getParams(1);
    console.log(param);
    sleep(20000);
    const sigSet = await InfraSS58.BBSPlus_createNewSigSet(DIDSet.did);
    await infraApi.bbsModule.addPublicKey(sigSet.publicKey);
    sleep(20000);
    const document = await infraApi.didModule.getDocument(true);
    console.log("document: ", JSON.stringify(document));
    sleep(20000);
    await infraApi.bbsModule.removePublicKey(3);
    sleep(20000);
    await infraApi.bbsModule.removeParams(1);
    sleep(20000);

    const authorizerId = infraApi.trustModule.createNewAuthorizerId();
    sleep(20000);
    await infraApi.trustModule.registerAuthorizer(authorizerId);
    sleep(20000);
    await infraApi.trustModule.getAuthorizer(authorizerId);
    sleep(20000);
    await infraApi.trustModule.addIssuer(authorizerId, DIDSet2.did);
    sleep(20000);
    await infraApi.trustModule.getIssuers(authorizerId, DIDSet2.did);
    sleep(20000);
    await infraApi.trustModule.removeIssuer(authorizerId, DIDSet2.did);
    sleep(20000);
    await infraApi.trustModule.addVerifier(authorizerId, DIDSet2.did);
    sleep(20000);
    await infraApi.trustModule.getVerifiers(authorizerId, DIDSet2.did);
    sleep(20000);
    await infraApi.trustModule.removeVerifier(authorizerId, DIDSet2.did);
    sleep(20000);
    await infraApi.trustModule.unregisterAuthorizer(authorizerId);


    sleep(20000);
    await infraApi.didModule.unregisterOnChain();
}

main();

