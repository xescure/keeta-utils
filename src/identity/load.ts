import * as KeetaNet from '@keetanetwork/keetanet-client';
import type { UserClient } from '@keetanetwork/keetanet-client';
import type { UserClientBuilder } from '@keetanetwork/keetanet-client/client/builder.js';
import { accountKeyAlgorithm, parseAddress, upstreamKeyAlgorithm } from './account.js';
import type { Account, GenericAccount } from './account.js';
import { createDriverRegistry, defaultIndex, defaultKeyAlgorithm, defaultKeyFormat } from './drivers.js';
import type { Driver, DriverContext, DriverRegistry, Environment } from './drivers.js';
import { decodeEnvironment } from './environment.js';
import { KeyConfigError } from './error.js';
import type { KeyConfigIssue, KeyConfigIssueCode } from './error.js';
import { formatKeyRef } from './keyref.js';
import type { DriverKeyRef } from './keyref.js';
import { checkPassphraseText, checkSeedText } from './material.js';
import { analyzeKeyConfig, checkExpectedAccount, checkUnknownVariables, fieldIssue } from './rules.js';
import type { Slot } from './rules.js';
import type { FeePayer, KeySpec, Loaded } from './schema.js';

export interface LoadKeysOptions {
	readonly env: Environment;
	readonly drivers: readonly Driver[];
}

/**
 * Decodes the environment and checks every static rule, reporting all
 * issues at once; only then reads the keys, again reporting every issue.
 */
export async function loadKeys<S extends KeySpec>(spec: S, options: LoadKeysOptions): Promise<Loaded<S>> {
	const registry = createDriverRegistry(options.drivers);
	const analysis = analyzeKeyConfig(spec, decodeEnvironment(spec, options.env), registry);
	KeyConfigError.throwIfAny([...analysis.issues, ...checkUnknownVariables(spec, options.env, analysis.referencedVariables)]);

	const issues: KeyConfigIssue[] = [];
	const accounts = new Map<string, GenericAccount>();
	const signers = new Map<string, Account>();
	for (const slot of analysis.slots) {
		const account = await loadSlot(slot, registry, { env: options.env }, issues);
		if (account === undefined) {
			continue;
		}
		accounts.set(slot.field.path, account);
		if (slot.field.block.kind === 'signer') {
			// loadSlot has checked that a signer's account is a key pair.
			signers.set(slot.field.path, account.assertAccount());
		}
	}
	KeyConfigError.throwIfAny(issues);

	const loaded: Record<string, unknown> = {};
	for (const [role, block] of Object.entries(spec.roles)) {
		if (block.kind === 'network') {
			loaded[role] = analysis.networks.get(role);
		} else if (block.kind !== 'actor') {
			loaded[role] = accounts.get(role);
		} else {
			const signer = signers.get(`${role}.signer`);
			if (signer === undefined) {
				throw(new Error(`the signer of ${role} did not load, without an issue`));
			}
			const actor: Record<string, unknown> = {
				signer,
				account: accounts.get(`${role}.account`) ?? signer,
				network: analysis.networks.get(`${role}.network`)
			};
			if (block.options.feePayer !== undefined) {
				actor['feePayer'] = resolveFeePayer(signer, signers.get(`${role}.feePayer`), accounts.get(`${role}.feeAccount`));
			}
			loaded[role] = actor;
		}
	}
	// Each role was assembled from the fields of its own block.
	return(loaded as Loaded<S>);
}

async function loadSlot(slot: Slot, registry: DriverRegistry, context: DriverContext, issues: KeyConfigIssue[]): Promise<GenericAccount | undefined> {
	const ref = slot.ref;
	if (ref.kind === 'address') {
		return(KeetaNet.lib.Account.fromPublicKeyString(ref.address));
	}
	function report(code: KeyConfigIssueCode, message: string): undefined {
		issues.push(fieldIssue(slot.field, code, `${formatKeyRef(ref)}: ${message}`));
		return(undefined);
	}

	let account: GenericAccount | undefined;
	const driver = registry.driver(ref.scheme);
	try {
		if (driver?.kind === 'signer') {
			account = await driver.load(ref, context);
		} else if (driver?.kind === 'source') {
			account = await decode(ref, await driver.read(ref, context), report);
		}
	} catch (error) {
		// A driver's message may hold anything; only its KeyConfigError
		// issues are written to be shown.
		if (!KeyConfigError.isInstance(error)) {
			return(report('READ_FAILED', 'the driver failed'));
		}
		for (const found of error.issues) {
			report(found.code, found.message);
		}
		return(undefined);
	}
	if (account === undefined) {
		return(undefined);
	}
	if (slot.field.block.kind === 'signer') {
		const algorithm = accountKeyAlgorithm(account);
		if (!account.hasPrivateKey || algorithm === undefined) {
			return(report('SIGNER_REQUIRED', 'loaded an account that cannot sign'));
		}
		if (!slot.field.block.constraints.algorithms.includes(algorithm)) {
			report('ALGORITHM_UNSUPPORTED', `loaded a ${algorithm} key, which this role does not take`);
		}
	}
	issues.push(...checkExpectedAccount(account, slot));
	return(account);
}

type Report = (code: KeyConfigIssueCode, message: string) => undefined;

async function decode(ref: DriverKeyRef, bytes: Uint8Array, report: Report): Promise<GenericAccount | undefined> {
	let text: string;
	try {
		text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
	} catch {
		return(report('INVALID_CONTENT', 'the key is not UTF-8 text'));
	}
	const format = ref.format ?? defaultKeyFormat;
	if (format === 'public') {
		return(parseAddress(text.trim()) ?? report('INVALID_CONTENT', 'the value is not a keeta_ address'));
	}

	let check = checkSeedText(text);
	if (format === 'passphrase') {
		check = checkPassphraseText(text);
	}
	if (!check.valid) {
		return(report('INVALID_CONTENT', check.reason));
	}
	try {
		let seed: string | ArrayBuffer = check.content;
		if (format === 'passphrase') {
			seed = await KeetaNet.lib.Account.seedFromPassphrase(check.content);
		}
		return(KeetaNet.lib.Account.fromSeed(seed, ref.index ?? defaultIndex, upstreamKeyAlgorithm(ref.alg ?? defaultKeyAlgorithm)));
	} catch (error) {
		return(report('INVALID_CONTENT', `upstream rejected the ${format}${upstreamCode(error)}`));
	}
}

/**
 * Upstream's error codes name the problem without the key, which its
 * messages may quote.
 */
function upstreamCode(error: unknown): string {
	if (typeof error !== 'object' || error === null) {
		return('');
	}
	const code: unknown = Reflect.get(error, 'code');
	if (typeof code === 'string' && /^[A-Z][A-Z0-9_]*$/.test(code)) {
		return(` (${code})`);
	}
	return('');
}

function resolveFeePayer(signer: Account, feePayerSigner: Account | undefined, feeAccount: GenericAccount | undefined): FeePayer | undefined {
	if (feePayerSigner !== undefined) {
		return({ signer: feePayerSigner, account: feeAccount ?? feePayerSigner });
	}
	if (feeAccount !== undefined) {
		return({ signer, account: feeAccount });
	}
	return(undefined);
}

type PublishOptions = NonNullable<Parameters<UserClientBuilder['publish']>[0]>;
export type GenerateFeeBlock = NonNullable<PublishOptions['generateFeeBlock']>;

/**
 * What the fee block generator needs of a `UserClient`.
 */
export interface FeeBlockClient {
	initBuilder(options?: Parameters<UserClient['initBuilder']>[0]): {
		computeFeeBlock(staple: Parameters<GenerateFeeBlock>[0], options: { readonly account: GenericAccount; readonly signer: Account }): ReturnType<GenerateFeeBlock>;
	};
}

/**
 * The `generateFeeBlock` option for publishing: upstream's default, with the
 * fee payer's account and signer.
 */
export function createFeeBlockGenerator(feePayer: FeePayer, client: FeeBlockClient): GenerateFeeBlock {
	return(function(staple, options) {
		return(client.initBuilder(options).computeFeeBlock(staple, { account: feePayer.account, signer: feePayer.signer }));
	});
}
