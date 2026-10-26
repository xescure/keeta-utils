import { expect, test } from 'vitest';
import { checkPassphraseText, checkSeedText, looksLikeKeyMaterial } from './material.js';

const seed = 'ab'.repeat(32);

test.each([
	seed,
	seed.toUpperCase(),
	`  ${seed}\n`,
	'one two three four five six seven eight nine ten eleven twelve',
	'one  two\tthree four five six seven eight nine ten eleven twelve thirteen'
])('%j looks like key material', function(value) {
	expect(looksLikeKeyMaterial(value)).toBe(true);
});

test.each([
	'env:ANCHOR_SEED',
	seed.slice(2),
	`${seed}00`,
	'one two three four five six seven eight nine ten eleven',
	'keeta_aabjufruwewrr4ihkrmolwabqtmzrwknzxm2mk6dyyzed2q6wlapdo5wdjtlwdy'
])('%j does not', function(value) {
	expect(looksLikeKeyMaterial(value)).toBe(false);
});

test('a seed is 64 hex digits after trimming, and the reason never shows it', function() {
	expect(checkSeedText(`${seed}\n`)).toStrictEqual({ valid: true, content: seed });
	for (const text of ['', seed.slice(1), `${seed}0`, `0x${seed}`, seed.replace('a', 'g')]) {
		const result = checkSeedText(text);
		expect(result.valid).toBe(false);
		expect(JSON.stringify(result)).not.toContain(seed.slice(0, 16));
	}
});

test('a passphrase is non-empty after trimming', function() {
	expect(checkPassphraseText(' correct horse \n')).toStrictEqual({ valid: true, content: 'correct horse' });
	expect(checkPassphraseText(' \n\t').valid).toBe(false);
});
