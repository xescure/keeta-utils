import { describe, expect, test } from 'vitest';
import { createDriverRegistry } from './drivers.js';
import type { SignerCapabilities } from './drivers.js';
import { environmentSource } from './env.js';
import { parseKeyRef } from './keyref.js';
import { KeyConfigError } from './error.js';
import { loadKeys } from './load.js';
import { checkPublicRef, checkSignerRef } from './rules.js';
import { actor, defineKeys, network, publicAccount, signer } from './schema.js';
import type { SignerConstraints } from './schema.js';
import { remoteCapabilities, testAddress, testSeed, vaultSigner } from './test-support.js';

const secp256k1Address = testAddress(0);
const secp256r1Address = testAddress(1, 'secp256r1');

const handheld: SignerCapabilities = { algorithms: ['secp256r1'], purposes: ['block'], interactive: true, deterministic: true, publicKeyFrom: 'expect' };
const notary: SignerCapabilities = { ...remoteCapabilities, purposes: ['message'] };

// The rules see only declared capabilities: "device:" and "notary:" are
// scheme names that no rule knows.
const drivers = [
	environmentSource(),
	vaultSigner(),
	{ ...vaultSigner(handheld), scheme: 'device' },
	{ ...vaultSigner(notary), scheme: 'notary' }
];
const registry = createDriverRegistry(drivers);
const anyConstraints: SignerConstraints = signer({ interactive: 'allow', purposes: [] }).constraints;

function signerCodes(text: string, constraints: SignerConstraints, onMain: boolean): string[] {
	let onNetwork: 'main' | 'test' = 'test';
	if (onMain) {
		onNetwork = 'main';
	}
	return(checkSignerRef(parseKeyRef(text, registry), registry, constraints, onNetwork).map(function(found) {
		return(found.code);
	}));
}

function publicCodes(text: string): string[] {
	return(checkPublicRef(parseKeyRef(text, registry), registry).map(function(found) {
		return(found.code);
	}));
}

describe('positions', function() {
	test('a signerless position takes an address or a public-format source', function() {
		expect(publicCodes(secp256k1Address)).toStrictEqual([]);
		expect(publicCodes('env:TREASURY#format=public')).toStrictEqual([]);
	});

	test('a signerless position rejects a signer ref', function() {
		expect(publicCodes(`vault:1#expect=${secp256r1Address}`)).toStrictEqual(['SIGNER_IN_PUBLIC_POSITION']);
	});

	test('a public-only position rejects key material', function() {
		expect(publicCodes('env:TREASURY')).toStrictEqual(['MATERIAL_IN_PUBLIC_POSITION']);
		expect(publicCodes('env:TREASURY#format=passphrase')).toStrictEqual(['MATERIAL_IN_PUBLIC_POSITION']);
	});

	test('a signer position rejects a public ref', function() {
		expect(signerCodes(secp256k1Address, anyConstraints, false)).toStrictEqual(['SIGNER_REQUIRED']);
		expect(signerCodes('env:X#format=public', anyConstraints, false)).toStrictEqual(['SIGNER_REQUIRED']);
	});
});

describe('signer capabilities, checked as declared', function() {
	test('on main every signer needs expect; elsewhere only one that cannot report its key', function() {
		expect(signerCodes('env:X', anyConstraints, true)).toStrictEqual(['EXPECT_REQUIRED']);
		expect(signerCodes(`env:X#expect=${secp256k1Address}`, anyConstraints, true)).toStrictEqual([]);
		expect(signerCodes('env:X', anyConstraints, false)).toStrictEqual([]);
		expect(signerCodes('device:1', anyConstraints, false)).toStrictEqual(['EXPECT_REQUIRED']);
		const unknownNetwork = checkSignerRef(parseKeyRef('vault:1', registry), registry, anyConstraints, undefined);
		expect(unknownNetwork.map(function(found) {
			return(found.code);
		})).toStrictEqual(['EXPECT_REQUIRED']);
	});

	test('interactive, purposes and algorithms', function() {
		const forbid = signer({ purposes: [] }).constraints;
		expect(signerCodes(`device:1#expect=${secp256r1Address}`, forbid, false)).toStrictEqual(['INTERACTIVE_FORBIDDEN']);
		const blocks = signer({ interactive: 'allow' }).constraints;
		expect(signerCodes('notary:1', blocks, false)).toStrictEqual(['PURPOSE_UNSUPPORTED']);
		const edOnly = signer({ interactive: 'allow', purposes: [], algorithms: ['ed25519'] }).constraints;
		expect(signerCodes('env:X', edOnly, false)).toStrictEqual(['ALGORITHM_UNSUPPORTED']);
		expect(signerCodes('env:X#alg=ed25519', edOnly, false)).toStrictEqual([]);
		expect(signerCodes('vault:1', edOnly, false)).toStrictEqual(['ALGORITHM_UNSUPPORTED']);
		const r1Only = signer({ interactive: 'allow', purposes: [], algorithms: ['secp256r1'] }).constraints;
		expect(signerCodes(`vault:1#expect=${secp256k1Address}`, r1Only, false)).toStrictEqual(['ALGORITHM_UNSUPPORTED']);
		expect(signerCodes(`vault:1#expect=${secp256r1Address}`, r1Only, false)).toStrictEqual([]);
	});

	test('all of a ref\'s problems are reported together', function() {
		const strict = signer({ purposes: ['certificate'], algorithms: ['ed25519'] }).constraints;
		expect(signerCodes('device:1', strict, true)).toStrictEqual(['INTERACTIVE_FORBIDDEN', 'PURPOSE_UNSUPPORTED', 'ALGORITHM_UNSUPPORTED', 'EXPECT_REQUIRED']);
	});
});

describe('static rules through loadKeys', function() {
	const spec = defineKeys({
		anchor: actor({ signer: signer(), account: publicAccount(), feePayer: signer() }),
		treasury: publicAccount(),
		cold: signer(),
		network: network()
	});

	const valid = {
		ANCHOR_SIGNER: `env:ANCHOR_SEED#expect=${testAddress(0)}`,
		ANCHOR_NETWORK: 'main',
		ANCHOR_SEED: testSeed,
		TREASURY: secp256r1Address,
		COLD: 'env:COLD_SEED#index=1',
		COLD_SEED: testSeed,
		NETWORK: 'test'
	};

	async function issuesOf(env: Record<string, string>): Promise<string[]> {
		try {
			await loadKeys(spec, { env, drivers });
		} catch (error) {
			if (KeyConfigError.isInstance(error)) {
				return(error.issues.map(function(found) {
					return(`${found.code} ${found.location} ${found.role ?? ''}`.trim());
				}));
			}
			throw(error);
		}
		return([]);
	}

	test('a valid configuration loads', async function() {
		expect(await issuesOf(valid)).toStrictEqual([]);
	});

	test('every missing value is reported', async function() {
		expect(await issuesOf({})).toStrictEqual([
			'MISSING_KEY ANCHOR_NETWORK anchor.network',
			'MISSING_KEY ANCHOR_SIGNER anchor.signer',
			'MISSING_KEY TREASURY treasury',
			'MISSING_KEY COLD cold',
			'MISSING_KEY NETWORK network'
		]);
	});

	test('an empty variable is unset', async function() {
		expect(await issuesOf({ ...valid, TREASURY: '' })).toStrictEqual(['MISSING_KEY TREASURY treasury']);
	});

	test('every issue is reported at once, across roles, with variable and role', async function() {
		expect(await issuesOf({
			...valid,
			ANCHOR_SIGNER: secp256k1Address,
			ANCHOR_ACCOUNT: 'env:ANCHOR_SEED',
			ANCHOR_FEE_PAYER: 'env:FEE_SEED',
			ANCHOR_NETWORK: 'mainnet',
			TREASURY: `vault:1#expect=${secp256r1Address}`,
			ANCHOR_SINGER: 'env:X',
			NETWORK: 'main'
		})).toStrictEqual([
			'INVALID_NETWORK ANCHOR_NETWORK anchor.network',
			'SIGNER_REQUIRED ANCHOR_SIGNER anchor.signer',
			'MATERIAL_IN_PUBLIC_POSITION ANCHOR_ACCOUNT anchor.account',
			'EXPECT_REQUIRED ANCHOR_FEE_PAYER anchor.feePayer',
			'SIGNER_IN_PUBLIC_POSITION TREASURY treasury',
			'EXPECT_REQUIRED COLD cold',
			'UNKNOWN_VARIABLE ANCHOR_SINGER'
		]);
	});

	test('unknown variables under a prefix fail; those a ref reads and those outside every prefix do not', async function() {
		expect(await issuesOf({ ...valid, ANCHOR: 'x', TREASURY_ACCOUNT: 'x', PATH: '/bin', ANCHORAGE: 'x', ANCHOR_TYPO: '' })).toStrictEqual([
			'UNKNOWN_VARIABLE ANCHOR',
			'UNKNOWN_VARIABLE TREASURY_ACCOUNT'
		]);
	});

	test('a value that looks like key material is never shown', async function() {
		const seed = '12'.repeat(32);
		const found = await issuesOf({ ...valid, TREASURY: seed, COLD: `env:COLD#${seed}=1` });
		expect(JSON.stringify(found)).not.toContain(seed);
		expect(found).toStrictEqual(['KEY_MATERIAL_AS_REF TREASURY treasury', 'KEY_MATERIAL_AS_REF COLD cold', 'UNKNOWN_VARIABLE COLD_SEED']);
	});
});
