const typeIDProperty: unique symbol = Symbol.for('@xescure/keeta-utils/typeID');

/**
 * The base of the library's errors. Errors are recognized by a type ID rather
 * than by `instanceof`, which fails when two copies of the library are loaded.
 */
export abstract class TypedError extends Error {
	protected constructor(typeID: string, message: string) {
		super(message);
		Object.defineProperty(this, typeIDProperty, { value: typeID });
	}

	protected static hasTypeID(value: unknown, typeID: string): boolean {
		if (typeof value !== 'object' || value === null) {
			return(false);
		}
		return(Reflect.get(value, typeIDProperty) === typeID);
	}
}

export type KeyConfigIssueCode =
	| 'KEYREF_SYNTAX'
	| 'UNKNOWN_SCHEME'
	| 'UNKNOWN_PARAM'
	| 'REPEATED_PARAM'
	| 'INVALID_PARAM'
	| 'PARAM_NOT_ALLOWED'
	| 'INVALID_BODY'
	| 'INVALID_ADDRESS'
	| 'KEY_MATERIAL_AS_REF'
	| 'DUPLICATE_DRIVER'
	| 'INVALID_DRIVER'
	| 'INVALID_SCHEMA'
	| 'SIGNER_IN_PUBLIC_POSITION'
	| 'MATERIAL_IN_PUBLIC_POSITION'
	| 'SIGNER_REQUIRED'
	| 'EXPECT_REQUIRED'
	| 'INTERACTIVE_FORBIDDEN'
	| 'PURPOSE_UNSUPPORTED'
	| 'ALGORITHM_UNSUPPORTED'
	| 'EXPECT_MISMATCH'
	| 'UNKNOWN_VARIABLE'
	| 'MISSING_KEY'
	| 'INVALID_NETWORK'
	| 'INVALID_CONTENT'
	| 'READ_FAILED';

export type KeyConfigErrorCode = KeyConfigIssueCode | 'INVALID_KEY_CONFIGURATION';

/**
 * One problem with a key configuration. `location` is the variable (or ref)
 * the value came from and `role` the schema path, such as `anchor.signer`.
 * No field ever contains a value that failed to parse or any key material.
 */
export interface KeyConfigIssue {
	readonly code: KeyConfigIssueCode;
	readonly location: string;
	readonly role?: string;
	readonly message: string;
}

export class KeyConfigError extends TypedError {
	static readonly #typeID = 'KeyConfigError:2b0f6c1e-4f7a-4d1b-9a0e-6f3c8d5e7a21';

	override readonly name = 'KeyConfigError';
	readonly code: KeyConfigErrorCode;
	readonly issues: readonly KeyConfigIssue[];

	constructor(issues: readonly [KeyConfigIssue, ...KeyConfigIssue[]]) {
		super(KeyConfigError.#typeID, KeyConfigError.#describe(issues));
		this.issues = issues;
		if (issues.length === 1) {
			this.code = issues[0].code;
		} else {
			this.code = 'INVALID_KEY_CONFIGURATION';
		}
	}

	static isInstance(value: unknown): value is KeyConfigError {
		return(TypedError.hasTypeID(value, KeyConfigError.#typeID));
	}

	/**
	 * Throws one error that carries every issue, if there are any.
	 */
	static throwIfAny(issues: readonly KeyConfigIssue[]): void {
		const [first, ...rest] = issues;
		if (first !== undefined) {
			throw(new KeyConfigError([first, ...rest]));
		}
	}

	static #describe(issues: readonly KeyConfigIssue[]): string {
		const lines = issues.map(function(found) {
			let where = found.location;
			if (found.role !== undefined) {
				where = `${found.location} (${found.role})`;
			}
			return(`${where}: ${found.message} [${found.code}]`);
		});
		if (lines.length === 1) {
			return(lines.join(''));
		}
		return(`${lines.length} key configuration errors:\n${lines.join('\n')}`);
	}
}

export function issue(code: KeyConfigIssueCode, location: string, message: string, role?: string): KeyConfigIssue {
	if (role === undefined) {
		return({ code, location, message });
	}
	return({ code, location, role, message });
}
