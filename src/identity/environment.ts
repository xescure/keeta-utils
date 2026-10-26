import type { Environment } from './drivers.js';
import { fieldsOf } from './schema.js';
import type { ConfigText, KeySpec } from './schema.js';

/**
 * An actor `anchor` reads `ANCHOR_SIGNER`, `ANCHOR_ACCOUNT`,
 * `ANCHOR_FEE_PAYER`, `ANCHOR_FEE_ACCOUNT` and `ANCHOR_NETWORK`, as far as it
 * declares them; any other role reads its prefix alone. Only declared
 * variables are read, and an empty one is unset.
 */
export function decodeEnvironment(spec: KeySpec, env: Environment): ConfigText {
	const config: Record<string, string> = {};
	for (const field of fieldsOf(spec)) {
		const value = env[field.variable];
		if (value !== undefined && value !== '') {
			config[field.path] = value;
		}
	}
	return(config);
}

/**
 * The inverse of `decodeEnvironment`.
 */
export function encodeEnvironment(spec: KeySpec, config: ConfigText): Record<string, string> {
	const env: Record<string, string> = {};
	for (const field of fieldsOf(spec)) {
		const value = config[field.path];
		if (value !== undefined) {
			env[field.variable] = value;
		}
	}
	return(env);
}
