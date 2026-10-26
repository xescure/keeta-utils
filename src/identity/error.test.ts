import { expect, test } from 'vitest';
import { issue, KeyConfigError } from './error.js';

test('isInstance recognizes the type ID, not the class', function() {
	const error = new KeyConfigError([issue('MISSING_KEY', 'ANCHOR_SIGNER', 'not set')]);
	expect(KeyConfigError.isInstance(error)).toBe(true);

	// What a second copy of the library would throw: another class, with the
	// same type ID under the shared symbol.
	const copy = new Error('from another copy');
	Object.defineProperty(copy, Symbol.for('@xescure/keeta-utils/typeID'), { value: 'KeyConfigError:2b0f6c1e-4f7a-4d1b-9a0e-6f3c8d5e7a21' });
	expect(KeyConfigError.isInstance(copy)).toBe(true);

	expect(KeyConfigError.isInstance(new Error('plain'))).toBe(false);
	expect(KeyConfigError.isInstance({ code: 'MISSING_KEY', issues: [] })).toBe(false);
	expect(KeyConfigError.isInstance(undefined)).toBe(false);
});

test('one issue gives its own code; several give INVALID_KEY_CONFIGURATION', function() {
	const single = new KeyConfigError([issue('MISSING_KEY', 'ANCHOR_SIGNER', 'not set', 'anchor.signer')]);
	expect(single.code).toBe('MISSING_KEY');
	expect(single.message).toBe('ANCHOR_SIGNER (anchor.signer): not set [MISSING_KEY]');

	const several = new KeyConfigError([issue('MISSING_KEY', 'ANCHOR_SIGNER', 'not set'), issue('INVALID_NETWORK', 'ANCHOR_NETWORK', 'unknown')]);
	expect(several.code).toBe('INVALID_KEY_CONFIGURATION');
	expect(several.issues).toHaveLength(2);
	expect(several.message).toContain('ANCHOR_NETWORK: unknown [INVALID_NETWORK]');
});

test('throwIfAny throws only when there are issues', function() {
	expect(function() {
		KeyConfigError.throwIfAny([]);
	}).not.toThrow();
	expect(function() {
		KeyConfigError.throwIfAny([issue('MISSING_KEY', 'X', 'not set')]);
	}).toThrow('X: not set');
});
