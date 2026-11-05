import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as KeetaNet from '@keetanetwork/keetanet-client';
import { afterAll, describe, expect, test } from 'vitest';
import { createDriverRegistry } from './drivers.js';
import type { Driver } from './drivers.js';
import { environmentSource } from './env.js';
import { KeyConfigError } from './error.js';
import { credentialSource, fileSource } from './files.js';
import { formatKeyRef, parseKeyRef } from './keyref.js';
import { loadKeys } from './load.js';
import { defineKeys, network, signer } from './schema.js';
import { testAddress, testSeed } from './test-support.js';

const directory = await mkdtemp(join(tmpdir(), 'keeta-utils-'));
afterAll(async function() {
	await rm(directory, { recursive: true, force: true });
});

const passphrase = 'correct-horse-battery-staple-'.repeat(3);
const spec = defineKeys({ cold: signer(), network: network() });

/**
 * Where one source keeps a key named `name`: the ref, and the environment
 * that makes it readable once `store` has written the content.
 */
interface Source {
	readonly scheme: string;
	readonly drivers: readonly Driver[];
	ref(name: string): string;
	store(name: string, content: string): Promise<Record<string, string>>;
	missing(name: string): Record<string, string>;
}

const sources: Source[] = [
	{
		scheme: 'env',
		drivers: [environmentSource()],
		ref: function(name) {
			return(`env:${name}`);
		},
		store: async function(name, content) {
			return({ [name]: content });
		},
		missing: function() {
			return({});
		}
	},
	{
		scheme: 'file',
		drivers: [fileSource()],
		ref: function(name) {
			return(`file:${join(directory, 'files', name)}`);
		},
		store: async function(name, content) {
			await writeFile(join(directory, 'files', name), content);
			return({});
		},
		missing: function() {
			return({});
		}
	},
	{
		scheme: 'cred',
		drivers: [credentialSource()],
		ref: function(name) {
			return(`cred:${name}`);
		},
		store: async function(name, content) {
			await writeFile(join(directory, 'credentials', name), content);
			return({ CREDENTIALS_DIRECTORY: join(directory, 'credentials') });
		},
		missing: function() {
			return({ CREDENTIALS_DIRECTORY: join(directory, 'credentials') });
		}
	}
];
await mkdir(join(directory, 'files'));
await mkdir(join(directory, 'credentials'));

async function issuesOf(run: () => Promise<unknown>): Promise<readonly { code: string; location: string; message: string }[]> {
	try {
		await run();
	} catch (error) {
		if (KeyConfigError.isInstance(error)) {
			return(error.issues);
		}
		throw(error);
	}
	throw(new Error('expected a KeyConfigError'));
}

describe.each(sources)('the $scheme: source', function(source) {
	test('a seed, padded with whitespace, loads as its signer', async function() {
		const env = await source.store('SEED_A', `\n ${testSeed} \n`);
		const keys = await loadKeys(spec, { drivers: source.drivers, env: { ...env, COLD: `${source.ref('SEED_A')}#index=3`, NETWORK: 'test' } });
		expect(keys.cold.publicKeyString.toString()).toBe(testAddress(3));
	});

	test('a passphrase derives through upstream', async function() {
		const env = await source.store('PASSPHRASE_A', `${passphrase}\n`);
		const expected = KeetaNet.lib.Account.fromSeed(await KeetaNet.lib.Account.seedFromPassphrase(passphrase), 0);
		const keys = await loadKeys(spec, { drivers: source.drivers, env: { ...env, COLD: `${source.ref('PASSPHRASE_A')}#format=passphrase`, NETWORK: 'test' } });
		expect(keys.cold.publicKeyString.toString()).toBe(expected.publicKeyString.toString());
	});

	test('bad content is an error that names the variable and role, not the content', async function() {
		const content = `${testSeed.slice(0, 60)}zzzz`;
		const env = await source.store('BAD_A', content);
		const found = await issuesOf(function() {
			return(loadKeys(spec, { drivers: source.drivers, env: { ...env, COLD: source.ref('BAD_A'), NETWORK: 'test' } }));
		});
		expect(found.map(function(item) {
			return(`${item.code} ${item.location}`);
		})).toStrictEqual(['INVALID_CONTENT COLD']);
		expect(JSON.stringify(found)).not.toContain(content.slice(0, 16));
	});

	test('a missing source is a read failure that names the ref', async function() {
		const found = await issuesOf(function() {
			return(loadKeys(spec, { drivers: source.drivers, env: { ...source.missing('ABSENT_A'), COLD: source.ref('ABSENT_A'), NETWORK: 'test' } }));
		});
		expect(found.map(function(item) {
			return(item.code);
		})).toStrictEqual(['READ_FAILED']);
		expect(found[0]?.message).toContain(source.ref('ABSENT_A'));
	});

	test('an expect mismatch shows the public key, never the seed', async function() {
		const env = await source.store('SEED_B', testSeed);
		const found = await issuesOf(function() {
			return(loadKeys(spec, { drivers: source.drivers, env: { ...env, COLD: `${source.ref('SEED_B')}#expect=${testAddress(1)}`, NETWORK: 'test' } }));
		});
		expect(found[0]?.code).toBe('EXPECT_MISMATCH');
		expect(found[0]?.message).toContain(testAddress(0));
		expect(JSON.stringify(found)).not.toContain(testSeed);
	});
});

describe('file: bodies', function() {
	const registry = createDriverRegistry([fileSource()]);

	test.each([
		['file:/run/secrets/anchor', 'file:/run/secrets/anchor'],
		['file:///run/secrets/anchor', 'file:/run/secrets/anchor'],
		[`file:///a/b#format=passphrase&index=2&expect=${testAddress(2)}`, `file:/a/b#format=passphrase&index=2&expect=${testAddress(2)}`]
	])('%s formats as %s, which round-trips', function(text, canonical) {
		const ref = parseKeyRef(text, registry);
		expect(formatKeyRef(ref)).toBe(canonical);
		expect(parseKeyRef(canonical, registry)).toStrictEqual(ref);
	});

	test.each(['file:relative', 'file:', 'file:/', 'file://host/a', 'file:////a', 'file:/a//b', 'file:/a/./b', 'file:/a/../b', 'file:/a/'])('%s is rejected', function(text) {
		expect(function() {
			return(parseKeyRef(text, registry));
		}).toThrow(/INVALID_BODY/);
	});
});

describe('cred: bodies', function() {
	const registry = createDriverRegistry([credentialSource()]);

	test.each(['anchor', 'anchor.seed', 'anchor-seed_1', 'A'.repeat(255)])('%s is a credential name that round-trips', function(name) {
		const text = `cred:${name}#format=passphrase`;
		expect(formatKeyRef(parseKeyRef(text, registry))).toBe(text);
	});

	test.each(['cred:', 'cred:.hidden', 'cred:..', 'cred:a..b', 'cred:a/b', 'cred:a\\b', `cred:${'A'.repeat(256)}`])('%s is rejected', function(text) {
		expect(function() {
			return(parseKeyRef(text, registry));
		}).toThrow(/INVALID_BODY/);
	});

	test('without CREDENTIALS_DIRECTORY there is no fallback', async function() {
		const found = await issuesOf(function() {
			return(loadKeys(spec, { drivers: [credentialSource()], env: { COLD: 'cred:anchor', CREDENTIALS_DIRECTORY: '', NETWORK: 'test' } }));
		});
		expect(found.map(function(item) {
			return(`${item.code} ${item.location}`);
		})).toStrictEqual(['NO_CREDENTIALS_DIRECTORY COLD']);
	});
});

test('an empty or unreadable file is a read failure', async function() {
	const empty = join(directory, 'empty');
	const unreadable = join(directory, 'unreadable');
	await writeFile(empty, '');
	await writeFile(unreadable, testSeed);
	await chmod(unreadable, 0o000);
	const twoSpec = defineKeys({ cold: signer(), warm: signer(), network: network() });
	const found = await issuesOf(function() {
		return(loadKeys(twoSpec, { drivers: [fileSource()], env: { COLD: `file:${empty}`, WARM: `file:${unreadable}`, NETWORK: 'test' } }));
	});
	expect(found.map(function(item) {
		return(item.message);
	})).toStrictEqual([`file:${empty}: ${empty} is empty`, `file:${unreadable}: ${unreadable} cannot be read`]);
});

test('end to end: a systemd credential signs a block that upstream verifies', async function() {
	const credentials = join(directory, 'credentials');
	await writeFile(join(credentials, 'anchor-seed'), `${testSeed}\n`);
	const keys = await loadKeys(spec, {
		drivers: [credentialSource()],
		env: { COLD: `cred:anchor-seed#index=5&expect=${testAddress(5)}`, CREDENTIALS_DIRECTORY: credentials, NETWORK: 'main' }
	});
	const { Block } = KeetaNet.lib;
	const networkID = KeetaNet.Client.Config.NetworkIDs.main;
	const block = await new Block.Builder({
		version: 2,
		purpose: Block.Purpose.GENERIC,
		account: keys.cold,
		signer: keys.cold,
		network: networkID,
		previous: Block.NO_PREVIOUS,
		operations: [{ type: Block.OperationType.SEND, amount: 1n, to: KeetaNet.lib.Account.fromPublicKeyString(testAddress(9)), token: KeetaNet.lib.Account.generateBaseAddresses(networkID).baseToken }]
	}).seal();
	expect(new Block(block.toBytes()).hash.toString()).toBe(block.hash.toString());
});
