import { expect, test } from 'vitest';
import { decodeEnvironment, encodeEnvironment } from './environment.js';
import { actor, defineKeys, network, publicAccount, signer } from './schema.js';
import { testAddress } from './test-support.js';

const secp256k1Address = testAddress(0);
const secp256r1Address = testAddress(1, 'secp256r1');

const spec = defineKeys({
	anchor: actor({ signer: signer(), account: publicAccount(), feePayer: signer() }),
	backup: actor({ signer: signer() }),
	treasury: publicAccount(),
	network: network()
}, { prefixes: { treasury: 'KEETA_TREASURY' } });

const config = {
	'anchor.network': 'main',
	'anchor.signer': `env:ANCHOR_SEED#expect=${secp256k1Address}`,
	'anchor.account': secp256r1Address,
	'anchor.feePayer': 'env:FEE_SEED',
	'anchor.feeAccount': secp256k1Address,
	treasury: secp256r1Address,
	network: 'test'
};

const environment = {
	ANCHOR_NETWORK: 'main',
	ANCHOR_SIGNER: `env:ANCHOR_SEED#expect=${secp256k1Address}`,
	ANCHOR_ACCOUNT: secp256r1Address,
	ANCHOR_FEE_PAYER: 'env:FEE_SEED',
	ANCHOR_FEE_ACCOUNT: secp256k1Address,
	KEETA_TREASURY: secp256r1Address,
	NETWORK: 'test'
};

test('role anchor is ANCHOR_SIGNER, ANCHOR_ACCOUNT, ANCHOR_FEE_PAYER, ANCHOR_FEE_ACCOUNT and ANCHOR_NETWORK', function() {
	expect(encodeEnvironment(spec, config)).toStrictEqual(environment);
});

test('decode and encode are inverses', function() {
	expect(decodeEnvironment(spec, encodeEnvironment(spec, config))).toStrictEqual(config);
	expect(encodeEnvironment(spec, decodeEnvironment(spec, environment))).toStrictEqual(environment);
});

test('an empty variable is unset', function() {
	const decoded = decodeEnvironment(spec, { ...environment, ANCHOR_ACCOUNT: '', BACKUP_SIGNER: '', NETWORK: '' });
	expect(Object.keys(decoded)).toStrictEqual(['anchor.network', 'anchor.signer', 'anchor.feePayer', 'anchor.feeAccount', 'treasury']);
});

test('only declared variables are read', function() {
	expect(decodeEnvironment(spec, { ...environment, ANCHOR_SINGER: 'env:X', PATH: '/bin' })).toStrictEqual(config);
});
