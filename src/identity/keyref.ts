import { accountKeyAlgorithm, isKeyAlgorithm, keyAlgorithms, parseAddress } from './account.js';
import type { KeyAlgorithm } from './account.js';
import { defaultKeyAlgorithm, defaultKeyFormat, formatParams, keyFormats } from './drivers.js';
import type { Driver, DriverRegistry, KeyFormat, KeyParamName } from './drivers.js';
import { issue, KeyConfigError } from './error.js';
import type { KeyConfigIssue } from './error.js';
import { looksLikeKeyMaterial } from './material.js';

/**
 * A `keeta_` address: a public key or an identifier, never a signer.
 */
export interface AddressKeyRef {
	readonly kind: 'address';
	readonly address: string;
}

/**
 * `scheme:body#params`. Only the params written in the ref are present; a
 * missing one takes its default when the key is loaded.
 */
export interface DriverKeyRef {
	readonly kind: 'driver';
	readonly scheme: string;
	readonly body: string;
	readonly format?: KeyFormat;
	readonly index?: number;
	readonly alg?: KeyAlgorithm;
	readonly expect?: string;
	/**
	 * The driver's own params.
	 */
	readonly params: Readonly<Record<string, string>>;
}

export type KeyRef = AddressKeyRef | DriverKeyRef;

export const sharedParamNames = ['format', 'index', 'alg', 'expect'] as const;
export const maximumIndex: number = 2 ** 32 - 1;

const schemePattern = /^[a-z][a-z0-9+.-]*$/;
const indexPattern = /^(0|[1-9][0-9]*)$/;
// Whitespace and control characters, plus the characters the syntax reserves:
// "?" for a query and "," as a list separator.
const forbiddenCharacterPattern = /[\s\p{Cc}?,]/u;

type Issues = readonly [KeyConfigIssue, ...KeyConfigIssue[]];
export type KeyRefReading = { readonly ref: KeyRef; readonly issues: readonly [] } | { readonly ref: undefined; readonly issues: Issues };

/**
 * Parses a ref and reports every problem with it. No issue ever contains the
 * text, or any part of it: a value that fails to parse may be a secret.
 */
export function readKeyRef(text: string, registry: DriverRegistry, location: string, role?: string): KeyRefReading {
	function fail(code: KeyConfigIssue['code'], message: string): KeyRefReading {
		return({ ref: undefined, issues: [issue(code, location, message, role)] });
	}

	if (looksLikeKeyMaterial(text)) {
		return(fail('KEY_MATERIAL_AS_REF', 'the value looks like key material, not a key reference; it is not shown'));
	}
	if (text === '') {
		return(fail('KEYREF_SYNTAX', 'the key reference is empty'));
	}
	if (forbiddenCharacterPattern.test(text)) {
		return(fail('KEYREF_SYNTAX', 'a key reference must not contain whitespace, control characters, "?" or ","'));
	}

	if (text.startsWith('keeta_') && !text.includes(':')) {
		if (text.includes('#')) {
			return(fail('PARAM_NOT_ALLOWED', 'a keeta_ address takes no params'));
		}
		if (parseAddress(text) === undefined) {
			return(fail('INVALID_ADDRESS', 'not a valid keeta_ address in its lowercase form'));
		}
		return({ ref: { kind: 'address', address: text }, issues: [] });
	}

	const colon = text.indexOf(':');
	const scheme = text.slice(0, colon);
	if (colon < 1 || !schemePattern.test(scheme) || !URL.canParse(text)) {
		return(fail('KEYREF_SYNTAX', 'a key reference is a URL scheme:body[#params] or a keeta_ address'));
	}

	const hash = text.indexOf('#');
	let body = text.slice(colon + 1);
	let fragment: string | undefined;
	if (hash >= 0) {
		body = text.slice(colon + 1, hash);
		fragment = text.slice(hash + 1);
		if (fragment === '' || fragment.includes('#')) {
			return(fail('KEYREF_SYNTAX', 'params follow a single "#" and must not be empty'));
		}
	}
	if (body.includes('%')) {
		return(fail('KEYREF_SYNTAX', 'the body of a key reference is literal and must not contain "%"'));
	}
	if (looksLikeKeyMaterial(body)) {
		return(fail('KEY_MATERIAL_AS_REF', 'the body looks like key material; it is not shown'));
	}

	const driver = registry.driver(scheme);
	if (driver === undefined) {
		return(fail('UNKNOWN_SCHEME', `no driver is registered for the scheme; registered: ${registry.schemes().join(', ')}`));
	}

	const issues: KeyConfigIssue[] = [];
	const bodyProblem = driver.checkBody(body);
	if (bodyProblem !== undefined) {
		issues.push(issue('INVALID_BODY', location, `${scheme}: ${bodyProblem}`, role));
	}
	const params = readParams([...new URLSearchParams(fragment ?? '')], driver, function(code, message) {
		issues.push(issue(code, location, message, role));
	});
	const [first, ...rest] = issues;
	if (first !== undefined) {
		return({ ref: undefined, issues: [first, ...rest] });
	}
	return({ ref: { kind: 'driver', scheme, body, ...params }, issues: [] });
}

type Report = (code: KeyConfigIssue['code'], message: string) => void;
type ParamFields = Omit<DriverKeyRef, 'kind' | 'scheme' | 'body'>;
type Params = { -readonly [K in keyof ParamFields]: ParamFields[K] };

function isKeyFormat(value: string): value is KeyFormat {
	return(keyFormats.some(function(format) {
		return(format === value);
	}));
}

function readParams(entries: readonly [string, string][], driver: Driver, report: Report): Params {
	const params: Params = { params: {} };
	const driverParams: Record<string, string> = {};
	const seen = new Set<string>();
	let expectAlgorithm: KeyAlgorithm | undefined;

	for (const [name, value] of entries) {
		if (looksLikeKeyMaterial(name) || looksLikeKeyMaterial(value)) {
			report('KEY_MATERIAL_AS_REF', 'a param looks like key material; it is not shown');
			continue;
		}
		const validator = driver.params?.[name];
		if (seen.has(name)) {
			report('REPEATED_PARAM', 'a param appears more than once');
			continue;
		}
		seen.add(name);

		if (name === 'format') {
			if (isKeyFormat(value)) {
				params.format = value;
			} else {
				report('INVALID_PARAM', `format must be one of ${keyFormats.join(', ')}`);
			}
		} else if (name === 'index') {
			if (indexPattern.test(value) && Number(value) <= maximumIndex) {
				params.index = Number(value);
			} else {
				report('INVALID_PARAM', `index must be a decimal integer from 0 to ${maximumIndex}, without leading zeros`);
			}
		} else if (name === 'alg') {
			if (isKeyAlgorithm(value)) {
				params.alg = value;
			} else {
				report('INVALID_PARAM', `alg must be one of ${keyAlgorithms.join(', ')}`);
			}
		} else if (name === 'expect') {
			const account = parseAddress(value);
			if (account !== undefined) {
				expectAlgorithm = accountKeyAlgorithm(account);
			}
			if (expectAlgorithm === undefined) {
				report('INVALID_PARAM', 'expect must be the keeta_ address of a key pair, in its lowercase form');
			} else {
				params.expect = value;
			}
		} else if (validator === undefined) {
			report('UNKNOWN_PARAM', `a param is unknown to the ${driver.scheme}: driver and the shared params`);
		} else {
			const problem = validator(value);
			if (problem === undefined) {
				driverParams[name] = value;
			} else {
				report('INVALID_PARAM', `${name}: ${problem}`);
			}
		}
	}
	params.params = driverParams;

	let accepted: readonly KeyParamName[];
	let acceptor: string;
	if (driver.kind === 'source') {
		accepted = formatParams[params.format ?? defaultKeyFormat];
		acceptor = `the ${params.format ?? defaultKeyFormat} format`;
	} else {
		accepted = driver.sharedParams;
		acceptor = `the ${driver.scheme}: driver`;
		if (seen.has('format')) {
			report('PARAM_NOT_ALLOWED', `${acceptor} is a signer and takes no format`);
		}
	}
	for (const name of ['index', 'alg', 'expect'] as const) {
		if (seen.has(name) && !accepted.includes(name)) {
			report('PARAM_NOT_ALLOWED', `${acceptor} does not take ${name}`);
		}
	}

	let algorithm = params.alg;
	if (algorithm === undefined && driver.kind === 'source') {
		algorithm = defaultKeyAlgorithm;
	}
	if (expectAlgorithm !== undefined && algorithm !== undefined && accepted.includes('alg') && algorithm !== expectAlgorithm) {
		report('INVALID_PARAM', `expect is a ${expectAlgorithm} address but the key is ${algorithm}`);
	}
	return(params);
}

/**
 * Parses a ref, throwing a `KeyConfigError` with every problem found.
 */
export function parseKeyRef(text: string, registry: DriverRegistry, location: string = 'key reference'): KeyRef {
	const reading = readKeyRef(text, registry, location);
	if (reading.ref === undefined) {
		throw(new KeyConfigError(reading.issues));
	}
	return(reading.ref);
}

/**
 * The canonical form: the body as written, then the params present in the
 * order format, index, alg, expect, then the driver's own params by name,
 * encoded by `URLSearchParams`.
 */
export function formatKeyRef(ref: KeyRef): string {
	if (ref.kind === 'address') {
		return(ref.address);
	}
	const params = new URLSearchParams();
	for (const name of sharedParamNames) {
		const value = ref[name];
		if (value !== undefined) {
			params.append(name, String(value));
		}
	}
	for (const [name, value] of Object.entries(ref.params).sort()) {
		params.append(name, value);
	}
	const encoded = params.toString();
	if (encoded === '') {
		return(`${ref.scheme}:${ref.body}`);
	}
	return(`${ref.scheme}:${ref.body}#${encoded}`);
}
