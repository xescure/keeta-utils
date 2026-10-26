import type { Account, KeyAlgorithm } from './account.js';
import { issue, KeyConfigError } from './error.js';
import type { KeyConfigIssue } from './error.js';
import type { DriverKeyRef } from './keyref.js';

export const purposes = ['block', 'message', 'certificate'] as const;
export type Purpose = (typeof purposes)[number];

/**
 * What a signer can do, declared by its driver without contacting the backend.
 * Every capability rule is checked against these, never against a scheme name.
 */
export interface SignerCapabilities {
	readonly algorithms: readonly KeyAlgorithm[];
	readonly purposes: readonly Purpose[];
	readonly interactive: boolean;
	readonly deterministic: boolean;
	/**
	 * `backend`: the public key comes from the key itself or its backend.
	 * `expect`: the backend cannot report it, so the ref must carry `expect`.
	 */
	readonly publicKeyFrom: 'backend' | 'expect';
}

export type Environment = Readonly<Record<string, string | undefined>>;

export interface DriverContext {
	readonly env: Environment;
}

/**
 * Returns why a value is invalid, or undefined if it is valid. The reason
 * never includes the value.
 */
export type ParamValidator = (value: string) => string | undefined;

/**
 * A driver's own params, by name, beside the shared ones.
 */
export type ParamSchema = Readonly<Record<string, ParamValidator>>;

/**
 * The shared params a signer driver may accept. `format` is only ever
 * accepted by source drivers.
 */
export type KeyParamName = 'index' | 'alg' | 'expect';

interface DriverBase {
	readonly scheme: string;
	readonly params?: ParamSchema;
	/**
	 * Returns why a body is invalid, or undefined if it is valid. The reason
	 * never includes the body.
	 */
	checkBody(body: string): string | undefined;
	/**
	 * The environment variables the ref reads, which are therefore not
	 * unknown variables.
	 */
	readsVariables?(ref: DriverKeyRef): readonly string[];
}

/**
 * Reads key bytes from somewhere; the ref's format decides what they mean.
 * A `KeyConfigError` it throws is reported under the ref's variable.
 */
export interface SourceDriver extends DriverBase {
	readonly kind: 'source';
	read(ref: DriverKeyRef, context: DriverContext): Promise<Uint8Array>;
}

/**
 * Signs without handing out key material, through an `ExternalKeyPair`.
 */
export interface SignerDriver extends DriverBase {
	readonly kind: 'signer';
	readonly sharedParams: readonly KeyParamName[];
	capabilities(ref: DriverKeyRef): SignerCapabilities;
	load(ref: DriverKeyRef, context: DriverContext): Promise<Account>;
}

export type Driver = SourceDriver | SignerDriver;

export const keyFormats = ['seed', 'passphrase', 'public'] as const;
export type KeyFormat = (typeof keyFormats)[number];

export const defaultKeyFormat: KeyFormat = 'seed';
export const defaultKeyAlgorithm: KeyAlgorithm = 'secp256k1';
export const defaultIndex = 0;

/**
 * The shared params each format of a source ref accepts.
 */
export const formatParams: Readonly<Record<KeyFormat, readonly KeyParamName[]>> = {
	seed: ['index', 'alg', 'expect'],
	passphrase: ['index', 'alg', 'expect'],
	public: ['expect']
};

/**
 * Key material held in the process: it signs anything, without a human, with
 * the algorithm the ref names.
 */
export function localCapabilities(ref: DriverKeyRef): SignerCapabilities {
	return({
		algorithms: [ref.alg ?? defaultKeyAlgorithm],
		purposes,
		interactive: false,
		deterministic: true,
		publicKeyFrom: 'backend'
	});
}

export interface DriverRegistry {
	driver(scheme: string): Driver | undefined;
	schemes(): readonly string[];
}

const schemePattern = /^[a-z][a-z0-9+.-]*$/;
const paramNamePattern = /^[a-z][a-z0-9-]*$/;
const sharedParamNames: readonly string[] = ['format', 'index', 'alg', 'expect'];

/**
 * Rejects a duplicate or malformed scheme and a reserved or malformed param
 * name, all at once.
 */
export function createDriverRegistry(drivers: readonly Driver[]): DriverRegistry {
	const byScheme = new Map<string, Driver>();
	const issues: KeyConfigIssue[] = [];
	for (const driver of drivers) {
		const location = `driver ${driver.scheme}:`;
		if (!schemePattern.test(driver.scheme)) {
			issues.push(issue('INVALID_DRIVER', location, 'a scheme must match [a-z][a-z0-9+.-]*'));
			continue;
		}
		for (const name of Object.keys(driver.params ?? {})) {
			if (sharedParamNames.includes(name) || !paramNamePattern.test(name)) {
				issues.push(issue('INVALID_DRIVER', location, `the param name ${name} is reserved or invalid`));
			}
		}
		if (byScheme.has(driver.scheme)) {
			issues.push(issue('DUPLICATE_DRIVER', location, 'the scheme is already registered'));
			continue;
		}
		byScheme.set(driver.scheme, driver);
	}
	KeyConfigError.throwIfAny(issues);

	return({
		driver: function(scheme) {
			return(byScheme.get(scheme));
		},
		schemes: function() {
			return([...byScheme.keys()].sort());
		}
	});
}
