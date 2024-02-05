import { CRYPTO_INFO, InfraSS58, VerifiableCredential, VerifiablePresentation } from "../src/infra-ss58/index";

let infraApi: InfraSS58;

async function main() {
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
    cryptoInfo: CRYPTO_INFO.ED25519_2018,
  };

  infraApi = await InfraSS58.createAsync(conf);

  // IF DID is not registered on chain, register it.
  // await infraApi.didModule.registerOnChain();

  const DIDSet = await InfraSS58.createNewSS58DIDSet(networkId, CRYPTO_INFO.ED25519_2018);
  const didDocuments = await infraApi.didModule.getDocument();

  const vc = new VerifiableCredential("did:infra:space:15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5");
  vc.addContext('https://www.w3.org/2018/credentials/v1');
  vc.addContext('https://schema.org');
  vc.addType('VerifiableCredential');
  vc.addSubject({ id: conf.did, 테스트: '123', alumniOf: 'Example University', email: 'test@test.com' }); // Claim 넣기

  const signedVC = await vc.sign(await infraApi.didModule.getKeyDoc());
  const verifyVC = await signedVC.verify(infraApi);
  console.log("verifyVC: ", verifyVC);

  const vp = new VerifiablePresentation(vpId);
  vp.addContext('https://www.w3.org/2018/credentials/examples/v1');
  vc.addContext('https://schema.org');
  vp.setHolder(infraApi.didModule.did);
  vp.addCredential(vc);

  const signedVP = await vp.sign(infraApi, infraApi.getChallenge(), domain);
  const verifyVP = await signedVP.verify(infraApi, infraApi.getChallenge(), domain)
  console.log("verifyVP:", verifyVP)
}

main();