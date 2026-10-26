import type { DriverContext, SourceDriver } from './drivers.js';
import { issue, KeyConfigError } from './error.js';
import type { DriverKeyRef } from './keyref.js';

const variableNamePattern = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * `env:NAME`: the key bytes are the value of the variable `NAME` in the
 * environment given to the loader. An empty variable is unset.
 */
export function environmentSource(): SourceDriver {
	return({
		kind: 'source',
		scheme: 'env',
		checkBody: function(body: string): string | undefined {
			if (!variableNamePattern.test(body)) {
				return('the body must be an environment variable name, [A-Za-z_][A-Za-z0-9_]*');
			}
			return(undefined);
		},
		readsVariables: function(ref: DriverKeyRef): readonly string[] {
			return([ref.body]);
		},
		read: async function(ref: DriverKeyRef, context: DriverContext): Promise<Uint8Array> {
			const value = context.env[ref.body];
			if (value === undefined || value === '') {
				throw(new KeyConfigError([issue('READ_FAILED', `env:${ref.body}`, `${ref.body} is not set`)]));
			}
			return(new TextEncoder().encode(value));
		}
	});
}
