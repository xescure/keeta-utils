import { describe, expect, expectTypeOf, test } from 'vitest';
import type { Account, GenericAccount, Network } from './account.js';
import { KeyConfigError } from './error.js';
import { actor, defineKeys, network, publicAccount, screamingSnakeCase, signer } from './schema.js';
import type { FeePayer, Loaded } from './schema.js';

test.each([
	['anchor', 'ANCHOR'],
	['feeRecipients', 'FEE_RECIPIENTS'],
	['accountID', 'ACCOUNT_ID'],
	['baseURLPath', 'BASE_URL_PATH'],
	['feePayer', 'FEE_PAYER'],
	['node2Hosts', 'NODE2_HOSTS']
])('%s is %s in the environment', function(name, expected) {
	expect(screamingSnakeCase(name)).toBe(expected);
});

test('the loaded type follows the spec', function() {
	const spec = defineKeys({
		anchor: actor({ signer: signer(), account: publicAccount(), feePayer: signer() }),
		operator: actor({ signer: signer() }),
		treasury: publicAccount(),
		cold: signer(),
		network: network()
	});
	type Keys = Loaded<typeof spec>;
	expectTypeOf<Keys['anchor']['signer']>().toEqualTypeOf<Account>();
	expectTypeOf<Keys['anchor']['account']>().toEqualTypeOf<GenericAccount>();
	expectTypeOf<Keys['anchor']['feePayer']>().toEqualTypeOf<FeePayer | undefined>();
	expectTypeOf<Keys['anchor']['network']>().toEqualTypeOf<Network>();
	expectTypeOf<Keys['operator']>().not.toHaveProperty('feePayer');
	expectTypeOf<Keys['treasury']>().toEqualTypeOf<GenericAccount>();
	expectTypeOf<Keys['treasury']>().not.toHaveProperty('signer');
	expectTypeOf<Keys['cold']>().toEqualTypeOf<Account>();
	expectTypeOf<Keys['network']>().toEqualTypeOf<Network>();
});

test('signer defaults: blocks only, no human, any algorithm', function() {
	expect(signer().constraints).toStrictEqual({ purposes: ['block'], interactive: 'forbid', algorithms: ['secp256k1', 'secp256r1', 'ed25519'] });
});

describe('defineKeys rejects an invalid declaration', function() {
	function issuesOf(run: () => unknown): string[] {
		try {
			run();
		} catch (error) {
			if (KeyConfigError.isInstance(error)) {
				return(error.issues.map(function(found) {
					return(`${found.code} ${found.location}`);
				}));
			}
			throw(error);
		}
		return([]);
	}

	test('two roles that read the same variable', function() {
		expect(issuesOf(function() {
			return(defineKeys({ anchor: actor({ signer: signer() }), anchorSigner: publicAccount() }));
		})).toStrictEqual(['INVALID_SCHEMA anchorSigner']);
		expect(issuesOf(function() {
			return(defineKeys({ first: publicAccount(), second: publicAccount() }, { prefixes: { second: 'FIRST' } }));
		})).toStrictEqual(['INVALID_SCHEMA second']);
	});

	test('a malformed role name or prefix, or a prefix for no role', function() {
		expect(issuesOf(function() {
			return(defineKeys({ Anchor: publicAccount(), 'fee_payer': publicAccount(), treasury: publicAccount() }, { prefixes: { treasury: 'keeta_treasury' } }));
		})).toStrictEqual(['INVALID_SCHEMA Anchor', 'INVALID_SCHEMA fee_payer', 'INVALID_SCHEMA treasury']);
		const roles: Record<string, ReturnType<typeof publicAccount>> = { treasury: publicAccount() };
		expect(issuesOf(function() {
			return(defineKeys(roles, { prefixes: { other: 'OTHER' } }));
		})).toStrictEqual(['INVALID_SCHEMA other']);
	});
});
