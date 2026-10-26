import { accountKeyAlgorithm, isNetwork, parseAddress, publicKeyOf } from './account.js';
import type { GenericAccount, KeyAlgorithm, Network } from './account.js';
import { defaultKeyFormat, localCapabilities } from './drivers.js';
import type { DriverRegistry, Environment, SignerCapabilities } from './drivers.js';
import { issue } from './error.js';
import type { KeyConfigIssue, KeyConfigIssueCode } from './error.js';
import { formatKeyRef, readKeyRef } from './keyref.js';
import type { KeyRef } from './keyref.js';
import { fieldsOf } from './schema.js';
import type { ConfigText, Field, KeySpec, SignerConstraints } from './schema.js';

/**
 * A parsed ref and the field it fills.
 */
export interface Slot {
	readonly field: Field;
	readonly ref: KeyRef;
}

export interface Analysis {
	readonly issues: readonly KeyConfigIssue[];
	readonly networks: ReadonlyMap<string, Network>;
	/**
	 * Complete only when there are no issues.
	 */
	readonly slots: readonly Slot[];
	/**
	 * The variables the refs read, which are therefore not unknown.
	 */
	readonly referencedVariables: ReadonlySet<string>;
}

interface Problem {
	readonly code: KeyConfigIssueCode;
	readonly message: string;
}

export function fieldIssue(field: Field, code: KeyConfigIssueCode, message: string): KeyConfigIssue {
	return(issue(code, field.variable, message, field.path));
}

function signerCapabilities(ref: KeyRef, registry: DriverRegistry): SignerCapabilities | undefined {
	if (ref.kind === 'address') {
		return(undefined);
	}
	const driver = registry.driver(ref.scheme);
	if (driver?.kind === 'signer') {
		return(driver.capabilities(ref));
	}
	if ((ref.format ?? defaultKeyFormat) === 'public') {
		return(undefined);
	}
	return(localCapabilities(ref));
}

function expectedAlgorithm(ref: KeyRef): KeyAlgorithm | undefined {
	if (ref.kind === 'address' || ref.expect === undefined) {
		return(undefined);
	}
	const account = parseAddress(ref.expect);
	if (account === undefined) {
		return(undefined);
	}
	return(accountKeyAlgorithm(account));
}

/**
 * The static rules for a ref in a signer position, against the driver's
 * declared capabilities. `network` undefined is unknown, which counts as
 * `main`.
 */
export function checkSignerRef(ref: KeyRef, registry: DriverRegistry, constraints: SignerConstraints, network: Network | undefined): Problem[] {
	const capabilities = signerCapabilities(ref, registry);
	if (ref.kind === 'address' || capabilities === undefined) {
		return([{ code: 'SIGNER_REQUIRED', message: 'is public; this role needs a ref that can sign' }]);
	}
	const problems: Problem[] = [];
	if (constraints.interactive === 'forbid' && capabilities.interactive) {
		problems.push({ code: 'INTERACTIVE_FORBIDDEN', message: 'needs a human to sign, which this role forbids' });
	}
	const missingPurposes = constraints.purposes.filter(function(purpose) {
		return(!capabilities.purposes.includes(purpose));
	});
	if (missingPurposes.length > 0) {
		problems.push({ code: 'PURPOSE_UNSUPPORTED', message: `cannot sign for ${missingPurposes.join(', ')}` });
	}
	const expected = expectedAlgorithm(ref);
	const possible = capabilities.algorithms.filter(function(algorithm) {
		if (ref.alg !== undefined && ref.alg !== algorithm) {
			return(false);
		}
		if (expected !== undefined && expected !== algorithm) {
			return(false);
		}
		return(constraints.algorithms.includes(algorithm));
	});
	if (possible.length === 0) {
		problems.push({ code: 'ALGORITHM_UNSUPPORTED', message: `cannot be a ${constraints.algorithms.join(' or ')} key, which this role requires` });
	}
	if (ref.expect === undefined) {
		if (capabilities.publicKeyFrom === 'expect') {
			problems.push({ code: 'EXPECT_REQUIRED', message: 'cannot report its public key, so it needs #expect=keeta_...' });
		} else if (network === undefined || network === 'main') {
			problems.push({ code: 'EXPECT_REQUIRED', message: 'has no #expect=keeta_..., which every signer on main needs' });
		}
	}
	return(problems);
}

/**
 * The static rules for a ref in a signerless position.
 */
export function checkPublicRef(ref: KeyRef, registry: DriverRegistry): Problem[] {
	if (ref.kind === 'address') {
		return([]);
	}
	if (registry.driver(ref.scheme)?.kind === 'signer') {
		return([{ code: 'SIGNER_IN_PUBLIC_POSITION', message: 'is a signer; this role takes a keeta_ address or a #format=public ref' }]);
	}
	if ((ref.format ?? defaultKeyFormat) !== 'public') {
		return([{ code: 'MATERIAL_IN_PUBLIC_POSITION', message: 'holds key material; this role takes a keeta_ address or a #format=public ref' }]);
	}
	return([]);
}

/**
 * After loading: whether the key is the one its ref expects. The message
 * names the derived public key, never anything else about the key.
 */
export function checkExpectedAccount(account: GenericAccount, slot: Slot): KeyConfigIssue[] {
	if (slot.ref.kind === 'address' || slot.ref.expect === undefined || publicKeyOf(account) === slot.ref.expect) {
		return([]);
	}
	return([fieldIssue(slot.field, 'EXPECT_MISMATCH', `the key loaded as ${publicKeyOf(account)}, but the ref expects ${slot.ref.expect}`)]);
}

/**
 * Every rule that needs only the spec and the refs, so it runs before any
 * secret is read.
 */
export function analyzeKeyConfig(spec: KeySpec, config: ConfigText, registry: DriverRegistry): Analysis {
	const issues: KeyConfigIssue[] = [];
	const networks = new Map<string, Network>();
	const slots: Slot[] = [];
	const referencedVariables = new Set<string>();

	for (const field of fieldsOf(spec)) {
		const text = config[field.path];
		if (text === undefined) {
			if (field.required) {
				issues.push(fieldIssue(field, 'MISSING_KEY', 'not set'));
			}
			continue;
		}
		if (field.block.kind === 'network') {
			if (isNetwork(text)) {
				networks.set(field.path, text);
			} else {
				issues.push(fieldIssue(field, 'INVALID_NETWORK', 'must be one of the known network names'));
			}
			continue;
		}

		const reading = readKeyRef(text, registry, field.variable, field.path);
		issues.push(...reading.issues);
		const ref = reading.ref;
		if (ref === undefined) {
			continue;
		}
		if (ref.kind === 'driver') {
			for (const name of registry.driver(ref.scheme)?.readsVariables?.(ref) ?? []) {
				referencedVariables.add(name);
			}
		}
		let problems: Problem[];
		if (field.block.kind === 'signer') {
			problems = checkSignerRef(ref, registry, field.block.constraints, networkAt(config, field.networkPath));
		} else {
			problems = checkPublicRef(ref, registry);
		}
		for (const problem of problems) {
			issues.push(fieldIssue(field, problem.code, `${formatKeyRef(ref)} ${problem.message}`));
		}
		slots.push({ field, ref });
	}
	return({ issues, networks, slots, referencedVariables });
}

function networkAt(config: ConfigText, path: string | undefined): Network | undefined {
	if (path === undefined) {
		return(undefined);
	}
	const text = config[path];
	if (text === undefined || !isNetwork(text)) {
		return(undefined);
	}
	return(text);
}

/**
 * Every variable under a declared prefix (`PREFIX_*`, or a bare actor
 * prefix) that neither a role nor a ref reads, so that a typo fails.
 */
export function checkUnknownVariables(spec: KeySpec, env: Environment, referencedVariables: ReadonlySet<string>): KeyConfigIssue[] {
	const fields = fieldsOf(spec);
	const issues: KeyConfigIssue[] = [];
	for (const [name, value] of Object.entries(env)) {
		if (value === undefined || value === '' || referencedVariables.has(name)) {
			continue;
		}
		const declared = fields.some(function(field) {
			return(field.variable === name);
		});
		const underPrefix = fields.some(function(field) {
			return(name === field.prefix || name.startsWith(`${field.prefix}_`));
		});
		if (underPrefix && !declared) {
			issues.push(issue('UNKNOWN_VARIABLE', name, 'the variable is under a declared prefix but nothing reads it'));
		}
	}
	return(issues);
}
