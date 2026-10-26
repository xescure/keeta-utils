import * as KeetaNet from '@keetanetwork/keetanet-client';
import { publicKeyOf, upstreamKeyAlgorithm } from './account.js';
import type { Account, KeyAlgorithm } from './account.js';
import type { DriverKeyRef } from './keyref.js';
import type { SignerCapabilities, SignerDriver, SourceDriver } from './drivers.js';

/**
 * A public test seed: anyone can sign for the accounts derived from it.
 */
export const testSeed = '6b656574612d7574696c73207465737420736565643b207075626c6963212121';

export function testAccount(index: number, algorithm: KeyAlgorithm = 'secp256k1'): Account {
	return(KeetaNet.lib.Account.fromSeed(testSeed, index, upstreamKeyAlgorithm(algorithm)));
}

export function testAddress(index: number, algorithm: KeyAlgorithm = 'secp256k1'): string {
	return(publicKeyOf(testAccount(index, algorithm)));
}

export const remoteCapabilities: SignerCapabilities = {
	algorithms: ['secp256k1', 'secp256r1'],
	purposes: ['block', 'message', 'certificate'],
	interactive: false,
	deterministic: false,
	publicKeyFrom: 'backend'
};

/**
 * An invented signer driver, `vault:INDEX`, that signs remotely in spirit: it
 * hands out only an `ExternalKeyPair` over a test key, never the key.
 */
export function vaultSigner(capabilities: SignerCapabilities = remoteCapabilities): SignerDriver & { readonly loads: readonly string[] } {
	const loads: string[] = [];
	return({
		kind: 'signer',
		scheme: 'vault',
		sharedParams: ['alg', 'expect'],
		params: {
			region: function(value: string): string | undefined {
				if (!/^[a-z]+-[0-9]+$/.test(value)) {
					return('a region is like eu-1');
				}
				return(undefined);
			}
		},
		loads,
		capabilities: function(): SignerCapabilities {
			return(capabilities);
		},
		checkBody: function(body: string): string | undefined {
			if (!/^(0|[1-9][0-9]*)$/.test(body)) {
				return('the body is a key number');
			}
			return(undefined);
		},
		load: async function(ref: DriverKeyRef): Promise<Account> {
			loads.push(ref.body);
			const inner = testAccount(Number(ref.body), ref.alg ?? 'secp256r1');
			// The account hashes the data before an external key pair signs it.
			const external = new KeetaNet.lib.Account.ExternalKeyPair({
				supportsEncryption: false,
				sign: function(data, options) {
					return(inner.sign(data, { ...options, raw: true }));
				}
			}, inner.publicKey.get(), inner.keyType);
			return(new KeetaNet.lib.Account(external).assertAccount());
		}
	});
}

/**
 * A source that records what it reads, to show that nothing is read before
 * the static rules pass.
 */
export function recordingSource(values: Readonly<Record<string, string>>): SourceDriver & { readonly reads: readonly string[] } {
	const reads: string[] = [];
	return({
		kind: 'source',
		scheme: 'memory',
		reads,
		checkBody: function(): undefined {
			return(undefined);
		},
		read: async function(ref: DriverKeyRef): Promise<Uint8Array> {
			reads.push(ref.body);
			return(new TextEncoder().encode(values[ref.body] ?? ''));
		}
	});
}
