import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { expect, test } from 'vitest';

const sourceRoot = join(import.meta.dirname, '..');

function sourceFiles(directory: string): string[] {
	const files: string[] = [];
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		if (entry.isDirectory()) {
			files.push(...sourceFiles(path));
		} else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
			files.push(path);
		}
	}
	return(files);
}

function importsOf(path: string): string[] {
	const text = readFileSync(path, 'utf8');
	const found: string[] = [];
	for (const match of text.matchAll(/^(?:import|export)\s[^'"]*?from\s+'([^']+)'/gm)) {
		const specifier = match[1];
		if (specifier !== undefined) {
			found.push(specifier);
		}
	}
	return(found);
}

test('the library imports only upstream, Node built-ins and its own modules', function() {
	const files = sourceFiles(sourceRoot);
	expect(files.length).toBeGreaterThan(8);
	for (const file of files) {
		for (const specifier of importsOf(file)) {
			expect(specifier, `${relative(sourceRoot, file)} imports ${specifier}`).toMatch(/^(\.\.?\/|node:|@keetanetwork\/keetanet-client(\/|$))/);
		}
	}
});

test('no source names a scheme in a rule: the rules see only declared capabilities', function() {
	for (const name of ['rules.ts', 'load.ts', 'keyref.ts', 'drivers.ts', 'schema.ts']) {
		const text = readFileSync(join(sourceRoot, 'identity', name), 'utf8');
		expect(text, name).not.toMatch(/'(env|file|cred|gsm|kms|trezor)'/);
	}
});
