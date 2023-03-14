import vcExamplesV1 from './vc-examples-v1';
import ed25519V1Context from './ed25519-2020-v1-context.json';
import sr25519Context from './sr25519-context.json';
import secContext from './security_context';
import secContextV1 from './security-v1.json';
import didV1Context from './did-v1-updated.json';
import credV1Context from './credential-v1-updated.json';
import schema from './schema.json';
import odrl from './odrl.json';
import bbsV1Context from './bbs-v1.json';
import dockBBSV1Context from './dock-bbs-v1.json';
import dockPrettyVCContext from './prettyvc.json';

// Lookup of following URLs will lead to loading data from the context directory, this is done as the Sr25519 keys are not
// supported in any W3C standard and vc-js has them stored locally. This is a temporary solution.
//@ts-ignore
export default new Map([
    ['https://ld.dock.io/credentials/prettyvc', dockPrettyVCContext,],
    ['https://ld.dock.io/security/bbs/v1', dockBBSV1Context,],
    ['https://w3id.org/security/bbs/v1', bbsV1Context,],
    ['https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1/', bbsV1Context,],
    ['https://www.w3.org/2018/credentials/v1', credV1Context,],
    ['https://www.w3.org/2018/credentials/examples/v1', vcExamplesV1,],
    ['https://www.w3.org/ns/odrl.jsonld', odrl,],
    ['https://schema.org', schema,],
    ['http://schema.org', schema,],
    ['https://www.dock.io/2020/credentials/context/sr25519', sr25519Context,],
    ['https://w3id.org/security/v1', secContextV1,],
    ['https://w3id.org/security/v2', secContext,],
    ['https://w3id.org/did/v0.11', didV1Context,],
    ['https://www.w3.org/ns/did/v1', didV1Context,],
    ['https://w3id.org/security/suites/ed25519-2020/v1', ed25519V1Context,]
]);
