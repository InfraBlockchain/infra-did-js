import { randomAsHex } from '@polkadot/util-crypto';
import dock from './polkadot/dock/';
import { createNewDockDID } from './polkadot/dock/utils/did';
import { DockResolver } from './polkadot/dock//resolver';
import { DidKey, VerificationRelationship } from './polkadot/dock//public-keys';
import { getPublicKeyFromKeyringPair } from './polkadot/dock//utils/misc';
import VerifiableCredential from './polkadot/dock//verifiable-credential';
import VerifiablePresentation from './polkadot/dock//verifiable-presentation';
import getKeyDoc from './polkadot/dock//utils/vc/helpers';
import {
    createRandomRegistryId, OneOfPolicy, buildDockCredentialStatus, getDockRevIdFromCredential,
} from './polkadot/dock//utils/revocation';
import Schema from './polkadot/dock//modules/schema';

const CRYPTO = { SR25519: 'sr25519', ED25519: 'ed25519' };
Object.freeze(CRYPTO);

const issuerSeed = randomAsHex(32);
const holderSeed = randomAsHex(32);

const getSeed = () => randomAsHex(32);
const registerNewDIDUsingDIDKey = async (did, didKey) => await dock.did.new(did, [didKey], [], false);
const registerNewDIDUsingController = async (did, controller = []) => await dock.did.new(did, [], controller, false);

const resolver = new DockResolver(dock);

const resolve = async (did) => {
    const didDocument = await resolver.resolve(did);
    console.log('did resolver:', didDocument);
    return didDocument;
};

const resolve2 = async (did) => {
    const didDocument = await dock.did.getDocument(did);
    console.log('did resolve2:', didDocument);
    return didDocument;
};

const getDidKeyAndPair = async (seed, cryptoType, vr = new VerificationRelationship()) => {
    const pair = dock.keyring.addFromUri(seed, null, cryptoType);
    const publicKey = getPublicKeyFromKeyringPair(pair);
    console.log('pk::', publicKey.value);
    return { didKey: new DidKey(publicKey, vr), pair };
};

const addKey = async (did, pair) => {
    const { didKey } = await getDidKeyAndPair(getSeed(), CRYPTO.ED25519, new VerificationRelationship().setAssertion());
    await dock.did.addKeys([didKey], did, did, pair, 1, undefined, false);
};

const setup = async () => {
    // set account
    const alice = dock.keyring.addFromUri('//Alice');
    await dock.setAccount(alice);

    console.log('Register issuer');
    const issuerDID = createNewDockDID();
    const { didKey: issuerDIDKey, pair: issuerKeyPair } = await getDidKeyAndPair(issuerSeed, CRYPTO.ED25519);
    await registerNewDIDUsingDIDKey(issuerDID, issuerDIDKey);
    // eslint-disable-next-line operator-linebreak
    const issuerKeyDoc = getKeyDoc(issuerDID, issuerKeyPair, 'Ed25519VerificationKey2018');

    console.info('issuerDID: ', issuerDID);
    console.info('issuerDIDKey: ', issuerDIDKey);
    console.info('issuerKeyPair', issuerKeyPair);
    console.info('issuerKeyDoc', issuerKeyDoc);
    console.info('issuerSeed', issuerSeed);

    console.log('Register holder');
    const holderDID = createNewDockDID();
    const { didKey: holderDIDKey, pair: holderKeyPair } = await getDidKeyAndPair(holderSeed, CRYPTO.ED25519);
    await registerNewDIDUsingDIDKey(holderDID, holderDIDKey);

    // eslint-disable-next-line operator-linebreak
    const holderKeyDoc = getKeyDoc(holderDID, holderKeyPair, 'Ed25519VerificationKey2018');
    // create new policy
    const policy = new OneOfPolicy();
    policy.addOwner(issuerDID);

    // create new revocation registry with policy
    const registryId = createRandomRegistryId();
    await dock.revocation.newRegistry(registryId, policy, false, false);
    console.log('registryId::', registryId);
    return {
        alice, issuerDID, issuerDIDKey, issuerKeyPair, issuerKeyDoc, holderDID, holderDIDKey, holderKeyDoc, registryId,
    };
};

// wrapper
const dockWrapper = async (cb) => {
    await dock.init({ address: 'ws://localhost:9944' });
    const {
        alice, issuerDID, issuerDIDKey, issuerKeyPair, holderDID, holderDIDKey, registryId, issuerKeyDoc, holderKeyDoc,
    } = await setup();

    await cb({
        dock, alice, issuerDID, issuerDIDKey, issuerKeyPair, holderDID, holderDIDKey, holderKeyDoc, registryId, issuerKeyDoc,
    });

    await dock.revocation.removeRegistryWithOneOfPolicy(registryId, issuerDID, issuerKeyPair, 1, { didModule: dock.did }, false);
    await dock.disconnect();
};

const vpTest = async (vc, { holderKeyDoc, holderDID }) => {
    console.log('VP Test');

    const vpId = 'http://example.edu/credentials/2803';
    const vp = new VerifiablePresentation(vpId);
    const challenge = randomAsHex(32);
    const domain = 'example domain';
    console.log('default VP::: ', vp.toJSON());

    vp.addContext('https://www.w3.org/2018/credentials/examples/v1');
    vp.addType('CredentialManagerPresentation');
    vp.setHolder(holderDID);
    vp.addCredential(vc);
    console.log('updated VP::: ', vp.toJSON());

    const signedVP = await vp.sign(holderKeyDoc, challenge, domain);
    console.log('signed VP::: ', JSON.stringify(signedVP.toJSON(), null, 2));
    const verifyResult = await signedVP.verify({
        challenge,
        domain,
        resolver,
        compactProof: true,
        forceRevocationCheck: false,
    });
    console.log('verify VP::: ', verifyResult);
};
const schemaTest = async ({ issuerDID, issuerKeyPair }) => {
    console.log('Schema Test');
    let myNewSchema = new Schema();
    console.log('default Schema::: ', myNewSchema.toJSON());
    const someNewJSONSchema = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        description: 'Dock Schema Example',
        type: 'object',
        properties: {
            id: {
                type: 'string',
            },
            petid: {
                type: 'string',
            },
            emailAddress: {
                type: 'string',
                format: 'email',
            },
            alumniOf: {
                type: 'string',
            },
        },
        required: ['emailAddress', 'alumniOf'],
        additionalProperties: false,
    };
    myNewSchema = await myNewSchema.setJSONSchema(someNewJSONSchema);
    console.log('set json Schema::: ', myNewSchema.toJSON());
    console.log('Schema Blob::: ', myNewSchema.toBlob());

    await myNewSchema.writeToChain(dock, issuerDID, issuerKeyPair, 1);
    const result = await Schema.get(myNewSchema.id, dock);
    console.log('read schema on chain: ', result);
    return result;
};

const vcTest = async (init) => {
    const schema = await schemaTest(init);

    console.log('VC Test');
    const {
        holderDID, registryId, issuerKeyDoc, issuerDID, issuerKeyPair,
    } = init;
    const vcId = 'http://example.edu/credentials/1986';
    const vc = new VerifiableCredential(vcId);
    console.log('default VC::: ', vc.toJSON());
    const vcStatus = buildDockCredentialStatus(registryId);
    vc.addContext('https://www.w3.org/2018/credentials/examples/v1');
    // vc.addContext('https://pet-i.net/jsonld');
    vc.addType('AlumniCredential');
    vc.addSubject({ id: holderDID, alumniOf: 'Example University' });
    vc.setStatus(vcStatus);
    vc.setSchema(schema.id, 'JsonSchemaValidator2018');
    vc.setIssuanceDate('2020-01-01T14:48:48.486Z');
    vc.setExpirationDate('2999-01-01T14:48:48.486Z');
    console.log('updated VC::: ', vc.toJSON());

    const signedVC = await vc.sign(issuerKeyDoc);
    console.log('signedVC::: ', signedVC.toJSON());

    const verifyResult = await signedVC.verify({
        resolver,
        compactProof: true,
        forceRevocationCheck: true,
        revocationApi: { dock },
    });
    console.log('verify signedVC::: ', verifyResult);

    /// revoke and unrevoke VC
    const revokeId = getDockRevIdFromCredential(signedVC);
    let isRevoked = await dock.revocation.getIsRevoked(registryId, revokeId);
    console.log(' VC before Revoked::: ', isRevoked);
    await dock.revocation.revokeCredentialWithOneOfPolicy(registryId, revokeId, issuerDID, issuerKeyPair, 1, { didModule: dock.did }, false);
    isRevoked = await dock.revocation.getIsRevoked(registryId, revokeId);
    console.log(' VC Revoked::: ', isRevoked);
    await dock.revocation.unrevokeCredentialWithOneOfPolicy(registryId, revokeId, issuerDID, issuerKeyPair, 1, { didModule: dock.did }, false);
    isRevoked = await dock.revocation.getIsRevoked(registryId, revokeId);
    console.log(' VC Unrevoked::: ', isRevoked);
    await vpTest(vc, init);
};

const didTest = async () => {
    console.log('DID Test');
    const did = createNewDockDID();
    const did2 = createNewDockDID();
    console.log('dockDID >>>', did, did2);

    const { didKey, pair } = await getDidKeyAndPair(getSeed(), CRYPTO.SR25519, new VerificationRelationship().setAuthentication());

    await registerNewDIDUsingDIDKey(did, didKey);
    await resolve(did);

    await registerNewDIDUsingController(did2, [did]);
    await resolve2(did2);

    await addKey(did, pair);
    await resolve(did);
    console.log('didKey 1: ', await dock.did.getDidKey(did, 1));
    console.log('didKey 2: ', await dock.did.getDidKey(did, 2));

    await dock.did.remove(did, did, pair, 1, undefined, false);
};

dockWrapper(async (init) => {
    await didTest();
    await vcTest(init);
});
