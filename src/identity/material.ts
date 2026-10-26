const hexKeyPattern = /^[0-9a-fA-F]{64}$/;

/**
 * Whether a value that should be a ref looks like a secret instead: a 64-digit
 * hex seed or private key, or a passphrase of 12 or more words.
 */
export function looksLikeKeyMaterial(value: string): boolean {
	const trimmed = value.trim();
	if (hexKeyPattern.test(trimmed)) {
		return(true);
	}
	const words = trimmed.split(/\s+/).filter(function(word) {
		return(word !== '');
	});
	return(words.length >= 12);
}

export type ContentCheck = { readonly valid: true; readonly content: string } | { readonly valid: false; readonly reason: string };

/**
 * The content checks on bytes read from a source, after trimming. A reason
 * never includes the content.
 */
export function checkSeedText(text: string): ContentCheck {
	const trimmed = text.trim();
	if (!hexKeyPattern.test(trimmed)) {
		return({ valid: false, reason: 'a seed must be 64 hexadecimal digits' });
	}
	return({ valid: true, content: trimmed });
}

export function checkPassphraseText(text: string): ContentCheck {
	const trimmed = text.trim();
	if (trimmed === '') {
		return({ valid: false, reason: 'a passphrase must not be empty' });
	}
	return({ valid: true, content: trimmed });
}
