module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    testRegex: '(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$',
    transform: {
        "/node_modules/(@polkadot|@babel)/.+\\.(j|t)sx?$": "ts-jest",
        "^.+\\.js$": "babel-jest",
    },
    testPathIgnorePatterns: ["/node_modules/"],
    "moduleNameMapper": {
        "axios": "axios/dist/node/axios.cjs"
    },
    transformIgnorePatterns: [
        '/node_modules/(?!@polkadot|@babel|axios)',
        '!node_modules/'
    ],
    globals: {
        Uint8Array,
        Uint32Array,
        ArrayBuffer,
        TextDecoder,
        TextEncoder,
    },
    moduleFileExtensions: [
        'ts',
        'tsx',
        'js',
        'jsx',
        'json',
        'node'
    ],
    extensionsToTreatAsEsm: ['.ts']
};
