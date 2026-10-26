import * as KeetaNet from '@keetanetwork/keetanet-client';
import { describe, expect, test } from 'vitest';
import { createDriverRegistry } from './drivers.js';
import { environmentSource } from './env.js';
import { KeyConfigError } from './error.js';
import { formatKeyRef, parseKeyRef, readKeyRef } from './keyref.js';
import type { KeyRef } from './keyref.js';
import { testAddress, vaultSigner } from './test-support.js';

const secp256k1Address = testAddress(0);
const secp256r1Address = testAddress(1, 'secp256r1');
const ed25519Address = testAddress(2, 'ed25519');
const seed = '0f'.repeat(32);
const mnemonic = 'abandon ability able about above absent absorb abstract absurd abuse access accident';

const registry = createDriverRegistry([environmentSource(), vaultSigner()]);

function issuesOf(text: string): readonly { code: string; message: string; location: string }[] {
	return(readKeyRef(text, registry, 'TEST_VARIABLE').issues);
}

function codesOf(text: string): string[] {
	return(issuesOf(text).map(function(found) {
		return(found.code);
	}));
}

describe('canonical form', function() {
	const canonical = [
		'env:ANCHOR_SEED',
		'env:ANCHOR_SEED#format=passphrase',
		'env:ANCHOR_SEED#format=seed',
		`env:ANCHOR_SEED#index=7&alg=ed25519&expect=${ed25519Address}`,
		'env:TREASURY#format=public',
		`env:TREASURY#format=public&expect=${secp256k1Address}`,
		'env:ANCHOR_SEED#index=4294967295',
		`vault:3#alg=secp256r1&expect=${secp256r1Address}&region=eu-1`,
		secp256k1Address
	];

	test.each(canonical)('formatKeyRef(parseKeyRef(%s)) gives it back', function(text) {
		expect(formatKeyRef(parseKeyRef(text, registry))).toBe(text);
	});

	test.each(canonical)('parseKeyRef(formatKeyRef(ref)) gives the ref back for %s', function(text) {
		const ref = parseKeyRef(text, registry);
		expect(parseKeyRef(formatKeyRef(ref), registry)).toStrictEqual(ref);
	});

	test('params are written in a fixed order whatever order they were read in', function() {
		const ref = parseKeyRef(`env:X#expect=${secp256k1Address}&alg=secp256k1&index=3&format=seed`, registry);
		expect(formatKeyRef(ref)).toBe(`env:X#format=seed&index=3&alg=secp256k1&expect=${secp256k1Address}`);
	});

	test('a ref keeps only the params written in it, so an explicit default stays', function() {
		expect(parseKeyRef('env:X#index=0', registry)).toStrictEqual({ kind: 'driver', scheme: 'env', body: 'X', index: 0, params: {} });
		expect(parseKeyRef('env:X', registry)).toStrictEqual({ kind: 'driver', scheme: 'env', body: 'X', params: {} });
	});

	test('formatKeyRef of a constructed ref parses back to it', function() {
		const refs: KeyRef[] = [
			{ kind: 'driver', scheme: 'env', body: 'A', format: 'passphrase', index: 12, alg: 'secp256r1', params: {} },
			{ kind: 'driver', scheme: 'vault', body: '0', params: { region: 'us-2' } },
			{ kind: 'address', address: ed25519Address }
		];
		for (const ref of refs) {
			expect(parseKeyRef(formatKeyRef(ref), registry)).toStrictEqual(ref);
		}
	});
});

describe('syntax', function() {
	test.each([
		'',
		'env',
		':X',
		'Env:X',
		'env:X Y',
		'env:X?format=seed',
		'env:A,env:B',
		'env:X#',
		'env:X#index=1#alg=ed25519',
		'env:A%42'
	])('%j is a syntax error', function(text) {
		expect(codesOf(text)).toStrictEqual(['KEYREF_SYNTAX']);
	});

	test('an unknown scheme is an error that names the registered ones, not the value', function() {
		const found = issuesOf('stash:anchor');
		expect(found.map(function(item) {
			return(item.code);
		})).toStrictEqual(['UNKNOWN_SCHEME']);
		expect(found[0]?.message).toContain('registered: env, vault');
		expect(found[0]?.message).not.toContain('stash');
	});

	test('an unknown param is an error that does not echo its name', function() {
		const found = issuesOf('env:X#colour=blue');
		expect(found.map(function(item) {
			return(item.code);
		})).toStrictEqual(['UNKNOWN_PARAM']);
		expect(JSON.stringify(found)).not.toContain('colour');
	});

	test('a repeated param is an error', function() {
		expect(codesOf('env:X#index=1&index=1')).toStrictEqual(['REPEATED_PARAM']);
		expect(codesOf('vault:1#region=eu-1&region=eu-2')).toStrictEqual(['REPEATED_PARAM']);
	});

	test('every problem with one ref is reported at once', function() {
		expect(codesOf('env:1X#index=01&alg=rsa&format=pem')).toStrictEqual(['INVALID_BODY', 'INVALID_PARAM', 'INVALID_PARAM', 'INVALID_PARAM']);
	});

	test('parseKeyRef throws a KeyConfigError with every issue', function() {
		let caught: unknown;
		try {
			parseKeyRef('env:X#index=-1&alg=rsa', registry, 'ANCHOR_SIGNER');
		} catch (error) {
			caught = error;
		}
		expect(KeyConfigError.isInstance(caught)).toBe(true);
		if (KeyConfigError.isInstance(caught)) {
			expect(caught.code).toBe('INVALID_KEY_CONFIGURATION');
			expect(caught.issues).toHaveLength(2);
			expect(caught.message).toContain('ANCHOR_SIGNER');
		}
	});
});

describe('shared params', function() {
	test.each([
		'env:X#index=4294967296',
		'env:X#index=1.5',
		'env:X#index=007',
		'env:X#alg=rsa',
		'env:X#format=privkey',
		'env:X#expect=keeta_nope',
		'vault:1#region=eu'
	])('%s is rejected', function(text) {
		expect(codesOf(text)).toStrictEqual(['INVALID_PARAM']);
	});

	test('expect must be the address of a key pair, not an identifier', function() {
		const token = KeetaNet.lib.Account.generateBaseAddresses(1n).baseToken.publicKeyString.toString();
		expect(codesOf(`env:X#expect=${token}`)).toStrictEqual(['INVALID_PARAM']);
	});

	test('expect must agree with alg, and with the default alg of a seed', function() {
		expect(codesOf(`env:X#alg=secp256r1&expect=${secp256k1Address}`)).toStrictEqual(['INVALID_PARAM']);
		expect(codesOf(`env:X#expect=${secp256r1Address}`)).toStrictEqual(['INVALID_PARAM']);
		expect(codesOf(`env:X#alg=secp256r1&expect=${secp256r1Address}`)).toStrictEqual([]);
		expect(codesOf(`vault:1#alg=secp256k1&expect=${secp256r1Address}`)).toStrictEqual(['INVALID_PARAM']);
	});

	test('index and alg are taken only where the format or driver allows them', function() {
		expect(codesOf('env:X#format=public&index=1')).toStrictEqual(['PARAM_NOT_ALLOWED']);
		expect(codesOf('env:X#format=public&alg=ed25519')).toStrictEqual(['PARAM_NOT_ALLOWED']);
		expect(codesOf('vault:1#index=1')).toStrictEqual(['PARAM_NOT_ALLOWED']);
		expect(codesOf('env:X#format=passphrase&index=1')).toStrictEqual([]);
	});

	test('a signer driver takes no format', function() {
		expect(codesOf('vault:1#format=seed')).toStrictEqual(['PARAM_NOT_ALLOWED']);
	});
});

describe('keeta_ refs', function() {
	test('an address is a public ref', function() {
		expect(parseKeyRef(secp256k1Address, registry)).toStrictEqual({ kind: 'address', address: secp256k1Address });
	});

	test('an address with a bad checksum, in uppercase or with params is rejected', function() {
		let last = 'a';
		if (secp256k1Address.endsWith('a')) {
			last = 'b';
		}
		expect(codesOf(`${secp256k1Address.slice(0, -1)}${last}`)).toStrictEqual(['INVALID_ADDRESS']);
		expect(codesOf(secp256k1Address.toUpperCase())).toStrictEqual(['KEYREF_SYNTAX']);
		expect(codesOf(`${secp256k1Address}#index=1`)).toStrictEqual(['PARAM_NOT_ALLOWED']);
	});
});

describe('key material where a ref is expected', function() {
	const material = [
		seed,
		` ${seed.toUpperCase()}\n`,
		mnemonic,
		`env:${'a'.repeat(64)}`,
		`vault:1#region=${seed}`,
		`env:X#${seed}=1`
	];

	test.each(material)('is rejected and never echoed: %#', function(text) {
		const found = issuesOf(text);
		expect(found.map(function(item) {
			return(item.code);
		})).toStrictEqual(['KEY_MATERIAL_AS_REF']);
		const shown = JSON.stringify(found).toLowerCase();
		expect(shown).not.toContain(seed);
		expect(shown).not.toContain('abandon');
		expect(shown).not.toContain('a'.repeat(64));
	});

	test('no issue of a ref that fails to parse contains any of it', function() {
		const secretish = 'hunter2-correct-horse';
		for (const text of [secretish, `${secretish}:x`, `env:${secretish}!`, `env:X#${secretish}=1`, `env:X#index=${secretish}`, `vault:${secretish}`]) {
			expect(JSON.stringify(issuesOf(text))).not.toContain(secretish);
		}
	});
});
