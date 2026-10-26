import type { Account, GenericAccount, KeyAlgorithm, Network } from './account.js';
import { keyAlgorithms } from './account.js';
import type { Purpose } from './drivers.js';
import { issue, KeyConfigError } from './error.js';
import type { KeyConfigIssue } from './error.js';

export interface SignerConstraints {
	readonly purposes: readonly Purpose[];
	readonly interactive: 'forbid' | 'allow';
	readonly algorithms: readonly KeyAlgorithm[];
}

export interface NetworkBlock {
	readonly kind: 'network';
}

/**
 * An account the program refers to but never signs for: a recipient, a
 * token, a multisig address.
 */
export interface PublicAccountBlock {
	readonly kind: 'publicAccount';
}

export interface SignerBlock {
	readonly kind: 'signer';
	readonly constraints: SignerConstraints;
}

export interface ActorOptions {
	readonly signer: SignerBlock;
	/**
	 * Declares `ACCOUNT`, the account the actor acts on; unset, the signer's.
	 */
	readonly account?: PublicAccountBlock;
	/**
	 * Declares `FEE_PAYER` and `FEE_ACCOUNT`; the block constrains the fee
	 * payer's signer. Both unset, the actor pays its own fees.
	 */
	readonly feePayer?: SignerBlock;
}

/**
 * A program identity: a signer on a network, the account it acts on and who
 * pays its fees.
 */
export interface ActorBlock<Options extends ActorOptions = ActorOptions> {
	readonly kind: 'actor';
	readonly options: Options;
}

export type Block = NetworkBlock | PublicAccountBlock | SignerBlock | ActorBlock;
export type Roles = Readonly<Record<string, Block>>;

export interface KeySpec<R extends Roles = Roles> {
	readonly kind: 'keySpec';
	readonly roles: R;
	/**
	 * Environment prefixes that replace the ones derived from role names.
	 */
	readonly prefixes: Readonly<Record<string, string>>;
}

export interface SignerOptions {
	readonly purposes?: readonly Purpose[];
	readonly interactive?: 'forbid' | 'allow';
	readonly algorithms?: readonly KeyAlgorithm[];
}

export function network(): NetworkBlock {
	return({ kind: 'network' });
}

export function publicAccount(): PublicAccountBlock {
	return({ kind: 'publicAccount' });
}

/**
 * By default a signer signs blocks, must not need a human, and may use any
 * algorithm.
 */
export function signer(options: SignerOptions = {}): SignerBlock {
	return({
		kind: 'signer',
		constraints: {
			purposes: options.purposes ?? ['block'],
			interactive: options.interactive ?? 'forbid',
			algorithms: options.algorithms ?? keyAlgorithms
		}
	});
}

export function actor<const Options extends ActorOptions>(options: Options): ActorBlock<Options> {
	return({ kind: 'actor', options });
}

export interface DefineKeysOptions<R extends Roles> {
	readonly prefixes?: { readonly [K in keyof R]?: string };
}

const roleNamePattern = /^[a-z][a-zA-Z0-9]*$/;
const prefixPattern = /^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$/;

/**
 * Declares what a program needs. Throws on a malformed role name or prefix,
 * a prefix for no role, or two roles that would read the same variable.
 */
export function defineKeys<const R extends Roles>(roles: R, options: DefineKeysOptions<R> = {}): KeySpec<R> {
	const prefixes: Record<string, string> = {};
	const issues: KeyConfigIssue[] = [];
	for (const [role, prefix] of Object.entries(options.prefixes ?? {})) {
		if (!Object.hasOwn(roles, role)) {
			issues.push(issue('INVALID_SCHEMA', role, 'a prefix is given for a role that is not declared'));
		} else if (prefix !== undefined) {
			prefixes[role] = prefix;
		}
	}
	for (const role of Object.keys(roles)) {
		if (!roleNamePattern.test(role)) {
			issues.push(issue('INVALID_SCHEMA', role, 'a role name must be camelCase, [a-z][a-zA-Z0-9]*'));
		} else if (!prefixPattern.test(prefixes[role] ?? screamingSnakeCase(role))) {
			issues.push(issue('INVALID_SCHEMA', role, 'a prefix must be SCREAMING_SNAKE_CASE, [A-Z][A-Z0-9]*(_[A-Z0-9]+)*'));
		}
	}
	const spec: KeySpec<R> = { kind: 'keySpec', roles, prefixes };
	const owners = new Map<string, string>();
	for (const field of fieldsOf(spec)) {
		const owner = owners.get(field.variable);
		if (owner !== undefined && owner !== field.role) {
			issues.push(issue('INVALID_SCHEMA', field.role, `the role reads ${field.variable}, which the role ${owner} reads too`));
		}
		owners.set(field.variable, field.role);
	}
	KeyConfigError.throwIfAny(issues);
	return(spec);
}

/**
 * One value a spec reads: a role's own, or one field of an actor.
 */
export interface Field {
	readonly role: string;
	/**
	 * `anchor.signer`, or the role name for a role that is a single value.
	 */
	readonly path: string;
	readonly prefix: string;
	readonly variable: string;
	readonly block: NetworkBlock | PublicAccountBlock | SignerBlock;
	readonly required: boolean;
	/**
	 * The path of the network a signer is on: its actor's, or the spec's only
	 * top-level network role. Undefined when there is none, which counts as
	 * `main`.
	 */
	readonly networkPath: string | undefined;
}

export function fieldsOf(spec: KeySpec): Field[] {
	const networkRoles = Object.keys(spec.roles).filter(function(role) {
		return(spec.roles[role]?.kind === 'network');
	});
	let schemaNetwork: string | undefined;
	if (networkRoles.length === 1) {
		schemaNetwork = networkRoles[0];
	}

	const fields: Field[] = [];
	for (const [role, block] of Object.entries(spec.roles)) {
		const prefix = spec.prefixes[role] ?? screamingSnakeCase(role);
		if (block.kind !== 'actor') {
			fields.push({ role, path: role, prefix, variable: prefix, block, required: true, networkPath: schemaNetwork });
			continue;
		}
		const networkPath = `${role}.network`;
		function add(name: string, fieldBlock: Field['block'], required: boolean): void {
			fields.push({ role, path: `${role}.${name}`, prefix, variable: `${prefix}_${screamingSnakeCase(name)}`, block: fieldBlock, required, networkPath });
		}
		add('network', { kind: 'network' }, true);
		add('signer', block.options.signer, true);
		if (block.options.account !== undefined) {
			add('account', block.options.account, false);
		}
		if (block.options.feePayer !== undefined) {
			add('feePayer', block.options.feePayer, false);
			add('feeAccount', { kind: 'publicAccount' }, false);
		}
	}
	return(fields);
}

function isUpper(character: string): boolean {
	return(character !== character.toLowerCase());
}

function isLower(character: string): boolean {
	return(character !== character.toUpperCase());
}

/**
 * `feeRecipients` to `FEE_RECIPIENTS`, keeping abbreviations whole:
 * `accountID` to `ACCOUNT_ID`, `baseURLPath` to `BASE_URL_PATH`.
 */
export function screamingSnakeCase(name: string): string {
	let result = '';
	const characters = [...name];
	for (const [position, character] of characters.entries()) {
		const previous = characters[position - 1];
		const next = characters[position + 1] ?? '';
		if (previous !== undefined && isUpper(character) && (!isUpper(previous) || isLower(next))) {
			result += '_';
		}
		result += character.toUpperCase();
	}
	return(result);
}

/**
 * Who pays an actor's fees: `signer` signs the fee block and `account` pays.
 * A fee payer signer alone pays from its own account; a fee account alone is
 * paid from by the actor's signer.
 */
export interface FeePayer {
	readonly signer: Account;
	readonly account: GenericAccount;
}

type LoadedFeePayer<O extends ActorOptions> = 'feePayer' extends keyof O ? { readonly feePayer: FeePayer | undefined } : Record<never, never>;

export type LoadedActor<O extends ActorOptions> = {
	readonly signer: Account;
	readonly account: GenericAccount;
	readonly network: Network;
} & LoadedFeePayer<O>;

export type LoadedBlock<B extends Block> =
	B extends NetworkBlock ? Network
		: B extends PublicAccountBlock ? GenericAccount
			: B extends SignerBlock ? Account
				: B extends ActorBlock<infer O> ? LoadedActor<O>
					: never;

/**
 * What `loadKeys` returns for a spec.
 */
export type Loaded<S extends KeySpec> = S extends KeySpec<infer R> ? { readonly [K in keyof R]: LoadedBlock<R[K]> } : never;

/**
 * A configuration as text, keyed by field path (`anchor.signer`,
 * `treasury`). Unset values are absent.
 */
export type ConfigText = Readonly<Record<string, string>>;
