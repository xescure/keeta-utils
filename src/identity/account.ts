import * as KeetaNet from '@keetanetwork/keetanet-client';
import type { Account, GenericAccount, KeyPairKeyAlgorithm } from '@keetanetwork/keetanet-client/lib/account.js';

export type { Account, GenericAccount };

export const networks: readonly Network[] = KeetaNet.Client.Config.networksArray;
export type Network = (typeof KeetaNet.Client.Config.networksArray)[number];

export const keyAlgorithms = ['secp256k1', 'secp256r1', 'ed25519'] as const;
export type KeyAlgorithm = (typeof keyAlgorithms)[number];

const AccountKeyAlgorithm: typeof KeetaNet.lib.Account.AccountKeyAlgorithm = KeetaNet.lib.Account.AccountKeyAlgorithm;

export function isNetwork(value: string): value is Network {
	return(networks.some(function(network) {
		return(network === value);
	}));
}

export function isKeyAlgorithm(value: string): value is KeyAlgorithm {
	return(keyAlgorithms.some(function(algorithm) {
		return(algorithm === value);
	}));
}

export function upstreamKeyAlgorithm(algorithm: KeyAlgorithm): KeyPairKeyAlgorithm {
	switch (algorithm) {
		case 'secp256k1':
			return(AccountKeyAlgorithm.ECDSA_SECP256K1);
		case 'secp256r1':
			return(AccountKeyAlgorithm.ECDSA_SECP256R1);
		case 'ed25519':
			return(AccountKeyAlgorithm.ED25519);
	}
}

/**
 * The algorithm of a key-pair account, or undefined for an identifier
 * (token, storage, network or multisig address).
 */
export function accountKeyAlgorithm(account: GenericAccount): KeyAlgorithm | undefined {
	switch (account.keyType) {
		case AccountKeyAlgorithm.ECDSA_SECP256K1:
			return('secp256k1');
		case AccountKeyAlgorithm.ECDSA_SECP256R1:
			return('secp256r1');
		case AccountKeyAlgorithm.ED25519:
			return('ed25519');
		default:
			return(undefined);
	}
}

/**
 * Parses a `keeta_` address. Only the canonical (lowercase) spelling with a
 * valid checksum is accepted, so that a ref has exactly one written form.
 */
export function parseAddress(text: string): GenericAccount | undefined {
	if (!text.startsWith('keeta_')) {
		return(undefined);
	}
	let account: GenericAccount;
	try {
		account = KeetaNet.lib.Account.fromPublicKeyString(text);
	} catch {
		return(undefined);
	}
	if (account.publicKeyString.toString() !== text) {
		return(undefined);
	}
	return(account);
}

export function publicKeyOf(account: GenericAccount): string {
	return(account.publicKeyString.toString());
}
