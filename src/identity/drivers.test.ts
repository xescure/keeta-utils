import { expect, test } from 'vitest';
import { createDriverRegistry } from './drivers.js';
import { environmentSource } from './env.js';
import { KeyConfigError } from './error.js';
import { vaultSigner } from './test-support.js';

function codesOf(run: () => unknown): string[] {
	try {
		run();
	} catch (error) {
		if (KeyConfigError.isInstance(error)) {
			return(error.issues.map(function(found) {
				return(found.code);
			}));
		}
		throw(error);
	}
	return([]);
}

test('a duplicate scheme is rejected, across source and signer drivers', function() {
	expect(codesOf(function() {
		return(createDriverRegistry([environmentSource(), environmentSource()]));
	})).toStrictEqual(['DUPLICATE_DRIVER']);
	expect(codesOf(function() {
		return(createDriverRegistry([environmentSource(), { ...vaultSigner(), scheme: 'env' }]));
	})).toStrictEqual(['DUPLICATE_DRIVER']);
});

test('malformed schemes and reserved or malformed param names are rejected, all at once', function() {
	const accept = function(): undefined {
		return(undefined);
	};
	expect(codesOf(function() {
		return(createDriverRegistry([
			{ ...vaultSigner(), scheme: 'Vault' },
			{ ...environmentSource(), scheme: 'stash', params: { index: accept } },
			{ ...environmentSource(), scheme: 'box', params: { Region: accept } }
		]));
	})).toStrictEqual(['INVALID_DRIVER', 'INVALID_DRIVER', 'INVALID_DRIVER']);
});

test('a registry knows its drivers by scheme', function() {
	const vault = vaultSigner();
	const registry = createDriverRegistry([environmentSource(), vault]);
	expect(registry.driver('vault')).toBe(vault);
	expect(registry.driver('file')).toBeUndefined();
	expect(registry.schemes()).toStrictEqual(['env', 'vault']);
});
