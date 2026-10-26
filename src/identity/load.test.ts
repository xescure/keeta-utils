import * as KeetaNet from '@keetanetwork/keetanet-client';
import { describe, expect, expectTypeOf, test } from 'vitest';
import type { Account, GenericAccount } from './account.js';
import { environmentSource } from './env.js';
import { KeyConfigError } from './error.js';
import { createFeeBlockGenerator, loadKeys } from './load.js';
import type { FeeBlockClient, GenerateFeeBlock } from './load.js';
import { actor, defineKeys, network, publicAccount, signer } from './schema.js';
import { recordingSource, testAccount, testAddress, testSeed, vaultSigner } from './test-support.js';

const { Block } = KeetaNet.lib;
const networkID = KeetaNet.Client.Config.NetworkIDs.test;
const passphrase = 'correct-horse-battery-staple-'.repeat(3);

async function signBlock(account: Account): Promise<InstanceType<typeof Block>> {
	const { baseToken } = KeetaNet.lib.Account.generateBaseAddresses(networkID);
	return(await new Block.Builder({
		version: 2,
		purpose: Block.Purpose.GENERIC,
		account,
		signer: account,
		network: networkID,
		previous: Block.NO_PREVIOUS,
		operations: [{ type: Block.OperationType.SEND, amount: 1n, to: testAccount(9), token: baseToken }]
	}).seal());
}

/**
 * Upstream validates every signature when it parses a block's bytes.
 */
function verifiedByUpstream(block: InstanceType<typeof Block>): boolean {
	return(new Block(block.toBytes()).hash.toString() === block.hash.toString());
}

async function issuesOf(run: () => Promise<unknown>): Promise<string[]> {
	try {
		await run();
	} catch (error) {
		if (KeyConfigError.isInstance(error)) {
			return(error.issues.map(function(found) {
				return(`${found.code} ${found.location}`);
			}));
		}
		throw(error);
	}
	throw(new Error('expected a KeyConfigError'));
}

const anchorSpec = defineKeys({
	anchor: actor({ signer: signer(), account: publicAccount(), feePayer: signer() }),
	treasury: publicAccount()
});

describe('end to end', function() {
	test('an env seed loads as a signer whose signed block upstream verifies', async function() {
		const keys = await loadKeys(anchorSpec, {
			drivers: [environmentSource()],
			env: {
				ANCHOR_SIGNER: `env:ANCHOR_SEED#index=4&expect=${testAddress(4)}`,
				ANCHOR_NETWORK: 'main',
				ANCHOR_SEED: `  ${testSeed}\n`,
				TREASURY: testAddress(7, 'ed25519')
			}
		});
		expect(keys.anchor.signer.publicKeyString.toString()).toBe(testAddress(4));
		expect(keys.anchor.account).toBe(keys.anchor.signer);
		expect(keys.anchor.network).toBe('main');
		expect(keys.anchor.feePayer).toBeUndefined();
		expect(keys.treasury.publicKeyString.toString()).toBe(testAddress(7, 'ed25519'));

		const block = await signBlock(keys.anchor.signer);
		expect(verifiedByUpstream(block)).toBe(true);
		const tampered = new Uint8Array(block.toBytes());
		tampered[tampered.length - 3] = (tampered[tampered.length - 3] ?? 0) ^ 1;
		expect(function() {
			return(new Block(tampered.buffer));
		}).toThrow();
	});

	test('a passphrase derives through upstream, with alg and index', async function() {
		const expected = KeetaNet.lib.Account.fromSeed(await KeetaNet.lib.Account.seedFromPassphrase(passphrase), 2, KeetaNet.lib.Account.AccountKeyAlgorithm.ED25519);
		const spec = defineKeys({ cold: signer(), network: network() });
		const keys = await loadKeys(spec, {
			drivers: [environmentSource()],
			env: { COLD: 'env:COLD_PASSPHRASE#format=passphrase&index=2&alg=ed25519', COLD_PASSPHRASE: passphrase, NETWORK: 'test' }
		});
		expect(keys.cold.publicKeyString.toString()).toBe(expected.publicKeyString.toString());
		expect(verifiedByUpstream(await signBlock(keys.cold))).toBe(true);
	});

	test('a signerless spec loads only public accounts', async function() {
		const spec = defineKeys({ treasury: publicAccount(), deposits: publicAccount() });
		const keys = await loadKeys(spec, {
			drivers: [environmentSource()],
			env: { TREASURY: testAddress(1), DEPOSITS: 'env:DEPOSIT_ADDRESS#format=public', DEPOSIT_ADDRESS: ` ${testAddress(2, 'secp256r1')} ` }
		});
		expectTypeOf(keys).toEqualTypeOf<{ readonly treasury: GenericAccount; readonly deposits: GenericAccount }>();
		expect(keys.treasury.hasPrivateKey).toBe(false);
		expect(keys.deposits.hasPrivateKey).toBe(false);
		expect(keys.deposits.publicKeyString.toString()).toBe(testAddress(2, 'secp256r1'));
	});

	test('an invented signer driver slots in without core changes', async function() {
		const vault = vaultSigner();
		const keys = await loadKeys(anchorSpec, {
			drivers: [environmentSource(), vault],
			env: {
				ANCHOR_SIGNER: `vault:3#expect=${testAddress(3, 'secp256r1')}&region=eu-1`,
				ANCHOR_FEE_PAYER: `env:FEE_SEED#index=5&expect=${testAddress(5)}`,
				ANCHOR_NETWORK: 'main',
				FEE_SEED: testSeed,
				TREASURY: testAddress(7)
			}
		});
		expect(vault.loads).toStrictEqual(['3']);
		expect(keys.anchor.signer.publicKeyString.toString()).toBe(testAddress(3, 'secp256r1'));
		expect(verifiedByUpstream(await signBlock(keys.anchor.signer))).toBe(true);
		expect(keys.anchor.feePayer?.signer.publicKeyString.toString()).toBe(testAddress(5));
		expect(keys.anchor.feePayer?.account).toBe(keys.anchor.feePayer?.signer);
	});
});

describe('fail-closed loading', function() {
	test('every static issue is reported at once, and nothing is read first', async function() {
		const memory = recordingSource({ ANCHOR_SEED: testSeed });
		const seed = '3c'.repeat(32);
		expect(await issuesOf(function() {
			return(loadKeys(anchorSpec, {
				drivers: [memory],
				env: { ANCHOR_SIGNER: 'memory:ANCHOR_SEED', ANCHOR_ACCOUNT: seed, ANCHOR_NETWORK: 'main', ANCHOR_SINGER: 'x', TREASURY: 'memory:T' }
			}));
		})).toStrictEqual([
			'EXPECT_REQUIRED ANCHOR_SIGNER',
			'KEY_MATERIAL_AS_REF ANCHOR_ACCOUNT',
			'MATERIAL_IN_PUBLIC_POSITION TREASURY',
			'UNKNOWN_VARIABLE ANCHOR_SINGER'
		]);
		expect(memory.reads).toStrictEqual([]);
	});

	test('an expect mismatch names the variable, the role and the derived public key', async function() {
		let caught: unknown;
		try {
			await loadKeys(anchorSpec, {
				drivers: [environmentSource()],
				env: { ANCHOR_SIGNER: `env:ANCHOR_SEED#expect=${testAddress(1)}`, ANCHOR_NETWORK: 'main', ANCHOR_SEED: testSeed, TREASURY: testAddress(2) }
			});
		} catch (error) {
			caught = error;
		}
		expect(KeyConfigError.isInstance(caught)).toBe(true);
		if (KeyConfigError.isInstance(caught)) {
			expect(caught.code).toBe('EXPECT_MISMATCH');
			expect(caught.message).toBe(`ANCHOR_SIGNER (anchor.signer): the key loaded as ${testAddress(0)}, but the ref expects ${testAddress(1)} [EXPECT_MISMATCH]`);
			expect(caught.message).not.toContain(testSeed);
		}
	});

	test('bad content and unset sources are reported together, without the content', async function() {
		const spec = defineKeys({ cold: signer(), hot: signer(), warm: signer(), treasury: publicAccount(), network: network() });
		const notHex = `${testSeed.slice(0, 63)}z`;
		const found = await issuesOf(function() {
			return(loadKeys(spec, {
				drivers: [environmentSource()],
				env: {
					COLD: 'env:COLD_SEED',
					COLD_SEED: notHex,
					HOT: 'env:HOT_SEED',
					WARM: 'env:WARM_PASSPHRASE#format=passphrase',
					WARM_PASSPHRASE: 'too short for upstream',
					TREASURY: 'env:TREASURY_ADDRESS#format=public',
					TREASURY_ADDRESS: 'keeta_not_an_address',
					NETWORK: 'test'
				}
			}));
		});
		expect(found).toStrictEqual(['INVALID_CONTENT COLD', 'READ_FAILED HOT', 'INVALID_CONTENT WARM', 'INVALID_CONTENT TREASURY']);
	});

	test('a driver\'s own failure is reported without its message', async function() {
		const failing = { ...vaultSigner(), load: async function(): Promise<Account> {
			throw(new Error(`backend said ${testSeed}`));
		} };
		const spec = defineKeys({ cold: signer(), network: network() });
		let caught: unknown;
		try {
			await loadKeys(spec, { drivers: [failing], env: { COLD: 'vault:1', NETWORK: 'test' } });
		} catch (error) {
			caught = error;
		}
		expect(KeyConfigError.isInstance(caught) && caught.code).toBe('READ_FAILED');
		expect(String(caught)).not.toContain(testSeed);
	});
});

describe('fee payer', function() {
	const env = {
		ANCHOR_SIGNER: `env:ANCHOR_SEED#expect=${testAddress(0)}`,
		ANCHOR_NETWORK: 'main',
		ANCHOR_SEED: testSeed,
		FEE_SEED: testSeed,
		TREASURY: testAddress(8)
	};
	const feeSigner = `env:FEE_SEED#index=5&expect=${testAddress(5)}`;

	test.each([
		['a fee payer signer pays from its own account', { ANCHOR_FEE_PAYER: feeSigner }, 5, 5],
		['a fee account is paid from by the actor\'s signer', { ANCHOR_FEE_ACCOUNT: testAddress(6) }, 0, 6],
		['both: the fee payer signs, the fee account pays', { ANCHOR_FEE_PAYER: feeSigner, ANCHOR_FEE_ACCOUNT: testAddress(6) }, 5, 6]
	])('%s', async function(_name, fee, signerIndex, accountIndex) {
		const keys = await loadKeys(anchorSpec, { drivers: [environmentSource()], env: { ...env, ...fee } });
		const feePayer = keys.anchor.feePayer;
		if (feePayer === undefined) {
			throw(new Error('expected a fee payer'));
		}
		expect(feePayer.signer.publicKeyString.toString()).toBe(testAddress(signerIndex));
		expect(feePayer.account.publicKeyString.toString()).toBe(testAddress(accountIndex));

		const sealed = await signBlock(feePayer.signer);
		const calls: { account: string; signer: string; options: unknown }[] = [];
		const client: FeeBlockClient = {
			initBuilder: function(options) {
				return({
					computeFeeBlock: async function(_staple, chosen) {
						calls.push({ account: chosen.account.publicKeyString.toString(), signer: chosen.signer.publicKeyString.toString(), options });
						return(sealed);
					}
				});
			}
		};
		const generate = createFeeBlockGenerator(feePayer, client);
		const staple = await KeetaNet.blockGenerator(testSeed, 0, 1, networkID);
		expect(await generate(staple, { usePublishAid: false })).toBe(sealed);
		expect(calls).toStrictEqual([{ account: testAddress(accountIndex), signer: testAddress(signerIndex), options: { usePublishAid: false } }]);
	});

	test('the generator is upstream\'s generateFeeBlock, and a UserClient is a fee block client', function() {
		expectTypeOf<GenerateFeeBlock>().toEqualTypeOf<NonNullable<NonNullable<Parameters<InstanceType<typeof KeetaNet.UserClient>['initBuilder']>[0]>['generateFeeBlock']>>();
		expectTypeOf<InstanceType<typeof KeetaNet.UserClient>>().toExtend<FeeBlockClient>();
	});
});
