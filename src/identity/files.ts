import { join } from 'node:path';
import type { DriverContext, SourceDriver } from './drivers.js';
import { issue, KeyConfigError } from './error.js';
import type { KeyConfigIssueCode } from './error.js';
import type { DriverKeyRef } from './keyref.js';

const credentialNamePattern = /^[A-Za-z0-9_-][A-Za-z0-9_.-]*$/;
const credentialsDirectory = 'CREDENTIALS_DIRECTORY';

function fail(location: string, message: string, code: KeyConfigIssueCode = 'READ_FAILED'): never {
	throw(new KeyConfigError([issue(code, location, message)]));
}

/**
 * Reads a whole file; a failure names the location and the file, never its
 * content.
 */
async function readKeyFile(path: string, location: string, context: DriverContext): Promise<Uint8Array> {
	let bytes: Uint8Array;
	try {
		bytes = await context.readFile(path);
	} catch (error) {
		if (typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT') {
			return(fail(location, `${path} does not exist`));
		}
		return(fail(location, `${path} cannot be read`));
	}
	if (bytes.length === 0) {
		return(fail(location, `${path} is empty`));
	}
	return(bytes);
}

/**
 * The absolute path of a `file:` body: `/x`, or `///x` with an empty host.
 */
function filePath(body: string): string {
	if (body.startsWith('///')) {
		return(body.slice(2));
	}
	return(body);
}

/**
 * `file:/absolute/path`: the key bytes are the contents of a file, such as a
 * Docker or Kubernetes secret. `file:///x` is accepted and written `file:/x`.
 */
export function fileSource(): SourceDriver {
	return({
		kind: 'source',
		scheme: 'file',
		checkBody: function(body: string): string | undefined {
			const path = filePath(body);
			if (!path.startsWith('/') || path.startsWith('//')) {
				return('the body must be an absolute path, /x or ///x');
			}
			const segments = path.slice(1).split('/');
			const plain = segments.every(function(segment) {
				return(segment !== '' && segment !== '.' && segment !== '..');
			});
			if (!plain) {
				return('the path must not have empty, "." or ".." segments, or a trailing "/"');
			}
			return(undefined);
		},
		canonicalBody: filePath,
		read: async function(ref: DriverKeyRef, context: DriverContext): Promise<Uint8Array> {
			return(readKeyFile(ref.body, `file:${ref.body}`, context));
		}
	});
}

/**
 * `cred:NAME`: the key bytes are the systemd credential `NAME`, the file
 * `$CREDENTIALS_DIRECTORY/NAME` that `LoadCredential=` provides. Without
 * that directory there is no fallback.
 */
export function credentialSource(): SourceDriver {
	return({
		kind: 'source',
		scheme: 'cred',
		checkBody: function(body: string): string | undefined {
			if (body.length > 255 || !credentialNamePattern.test(body) || body.includes('..')) {
				return('the body must be a credential file name, [A-Za-z0-9_.-]+, without a leading "." or "..", at most 255 characters');
			}
			return(undefined);
		},
		readsVariables: function(): readonly string[] {
			return([credentialsDirectory]);
		},
		read: async function(ref: DriverKeyRef, context: DriverContext): Promise<Uint8Array> {
			const location = `cred:${ref.body}`;
			const directory = context.env[credentialsDirectory];
			if (directory === undefined || directory === '') {
				return(fail(location, `${credentialsDirectory} is not set: the process is not running with systemd credentials`, 'NO_CREDENTIALS_DIRECTORY'));
			}
			return(readKeyFile(join(directory, ref.body), location, context));
		}
	});
}
