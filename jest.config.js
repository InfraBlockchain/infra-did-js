module.exports = {
    preset: 'ts-jest',
    bail: true,
    clearMocks: true,
    testTimeout: 30000,
    testEnvironment: 'node',
    testRegex: '(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$',
    transform: {
        "/node_modules/(@polkadot|@babel)/.+\\.(j|t)sx?$": "ts-jest",
        "^.+\\.js$": "babel-jest",
    },
    testPathIgnorePatterns: ["/node_modules/"],
    transformIgnorePatterns: [
        '/node_modules/(?!@polkadot|@babel)',
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
    // moduleNameMapper: {
    //     '^(\\.{1,2}/.*)\\.js$': '$1',
    // },
    extensionsToTreatAsEsm: ['.ts'],
    // coverageDirectory: './coverage/',
    // collectCoverageFrom: [
    //     'src/**/*.{ts,tsx}',
    //     '!src/**/*.d.ts',
    //     '!**/node_modules/**'
    // ]
};
