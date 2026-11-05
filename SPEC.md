# `@xescure/keeta-utils/identity`

How a Keeta program gets its keys.

The module is a thin layer over `@keetanetwork/keetanet-client` (peer dependency, `>=0.18.7 <0.19`).
Upstream does all key derivation (`Account.fromSeed`, `Account.seedFromPassphrase`, ...) and all external signing (`Account.ExternalKeyPair`, `KeetaGCPKMSKeyPairFactory`, `KeetaGCPKMSWrappedKeyPairFactory`).
This module adds only:

- where key bytes come from (drivers);
- validation of refs and of what they point at;
- roles, declared by the program;
- fail-closed rules;
- redaction.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

Every section is marked:

- **[implemented]**: implemented and tested;
- **[planned]**: designed, but not in the code.

A planned section MUST NOT need a change to an implemented interface. It plugs into the driver interface, the driver registry or the block union.

## Roadmap

1. `file:` and `cred:` sources [done]; the `keyring`, `list` and `optional` blocks.
2. The `gsm:` and `kms:` modules, and the `kms-wrapped` format.
3. The `trezor:` signer.
4. The flags and object codecs, only once a second user needs them.

## 1. Key references

A key reference ("ref") names a key without containing it.
Refs are durable configuration: they live in environment files, unit files and deployment manifests for years.

### 1.1 Syntax [implemented]

```
keyref      = driver-ref / address-ref
driver-ref  = scheme ":" body [ "#" params ]
address-ref = "keeta_" address
scheme      = lower *( lower / DIGIT / "+" / "-" / "." )
params      = param *( "&" param )      ; application/x-www-form-urlencoded
param       = name "=" value
```

- A driver ref MUST parse as a WHATWG `URL`. Its params are the fragment, parsed with `URLSearchParams`.
- The body is the text between the first `:` and the `#`, taken literally: no percent-decoding. Its syntax belongs to the driver.
- A ref MUST NOT contain:
  - whitespace or control characters;
  - `?`, which is reserved for queries;
  - `,`, which is reserved as the list separator (5.1).
- The body MUST NOT contain `%`.
- A ref has at most one `#`, and the fragment MUST NOT be empty.
- An address ref is the canonical (lowercase) `keeta_` encoding with a valid checksum, and takes no params.
- Each of these is an error:
  - an unknown scheme;
  - an unknown param;
  - a repeated param;
  - a param that the driver or format does not accept;
  - a malformed value.

### 1.2 Shared params

The core owns four params. A driver MAY declare params of its own, with validators (its `ParamSchema`). Those MUST NOT reuse the shared names.

| Param | Values | Default | Accepted by |
|---|---|---|---|
| `format` | `seed`, `passphrase`, `public` [implemented]; `privkey`, format drivers [planned] | `seed` | source drivers only |
| `index` | decimal `0`..`4294967295`, no leading zeros | `0` | formats `seed`, `passphrase`; signer drivers that declare it |
| `alg` | `secp256k1`, `secp256r1`, `ed25519` | `secp256k1` for source formats; none for signer drivers, whose backend decides | formats `seed`, `passphrase`; signer drivers that declare it |
| `expect` | the `keeta_` address of a key pair, not an identifier | none | every format; signer drivers that declare it |

`expect` MUST agree with `alg`, or with the default `alg` of a source format. [implemented]

### 1.3 Canonical form [implemented]

`formatKeyRef` writes the scheme and the body as parsed. Then it writes the params present, in the order `format`, `index`, `alg`, `expect`, followed by the driver params sorted by name. The params are encoded by `URLSearchParams`.

A parsed ref records only the params written in it. An explicit default such as `#index=0` is kept, so no two texts parse to the same ref.

- `parseKeyRef(formatKeyRef(ref))` MUST equal `ref`.
- `formatKeyRef(parseKeyRef(text))` MUST equal `text` for every canonical `text`.

### 1.4 Durability [implemented]

The syntax MUST only change additively: a new scheme, a new param or a new format. A ref valid today MUST keep its meaning. Anything unknown MUST fail at boot.

### 1.5 Redaction [implemented]

- A value that fails to parse may be a secret. No error contains it or any part of it: not its scheme, its body or its param names.
- Errors name the variable, the role and the reason. They also list the registered schemes where that helps.
- A ref that parsed MAY be shown, in canonical form.

## 2. Drivers

### 2.1 The driver interface [implemented]

These interfaces are final. New drivers implement them, and the core does not change.

```ts
interface DriverBase {
	scheme: string;
	params?: ParamSchema;                       // the driver's own params
	checkBody(body): string | undefined;        // a reason, never the body
	canonicalBody?(body): string;               // the one spelling of a valid body
	readsVariables?(ref): readonly string[];    // exempt from rule 11
}
interface SourceDriver extends DriverBase {
	kind: 'source';
	read(ref, { env, readFile }): Promise<Uint8Array>; // the format decides the meaning
}
interface SignerDriver extends DriverBase {
	kind: 'signer';
	sharedParams: ('index' | 'alg' | 'expect')[];
	capabilities(ref): SignerCapabilities;      // static: no backend call
	load(ref, { env }): Promise<Account>;       // built on ExternalKeyPair
}
interface SignerCapabilities {
	algorithms: KeyAlgorithm[];
	purposes: ('block' | 'message' | 'certificate')[];
	interactive: boolean;
	deterministic: boolean;
	publicKeyFrom: 'backend' | 'expect';
}
```

- `createDriverRegistry(drivers)` rejects a duplicate scheme, a malformed scheme (`[a-z][a-z0-9+.-]*`) and a reserved or malformed param name, all at once. Source and signer drivers share one scheme namespace.
- When a driver throws a `KeyConfigError`, its issues are reported under the ref's variable. Any other error is reported as `READ_FAILED`, without its message, because the message may hold anything.
- Key material held in the process has local capabilities:
  - the ref's `alg`;
  - every purpose;
  - not interactive;
  - deterministic;
  - public key from the backend.
- Upstream quirk: `Account.sign` hashes the data before it calls an `ExternalKeyPair`, but still passes `raw: false`. A signer that wraps another key MUST therefore sign the data as given (`raw: true`).

### 2.2 Source drivers

| Scheme | Body | Bytes | Status |
|---|---|---|---|
| `env` | `[A-Za-z_][A-Za-z0-9_]*` | the variable's value, from the `env` given to the loader | implemented |
| `file` | an absolute path with no empty, `.` or `..` segments and no trailing `/`; `///x` is accepted and written `/x` | the file's contents | implemented |
| `cred` | a systemd credential file name, `[A-Za-z0-9_.-]+` with no leading `.` and no `..`, at most 255 characters | `$CREDENTIALS_DIRECTORY/NAME` | implemented |
| `gsm` | `projects/p/secrets/s[/versions/v\|latest]` | the secret version's payload | planned (roadmap 2), module `./identity/gsm` |

- `env` reads only from the `env` passed to the loader, and an empty variable is unset. The variable it names is exempt from rule 11.
- `file:` covers Docker and Kubernetes secrets and the `_FILE` convention. `cred:` reads the files of systemd's `LoadCredential=`; it declares `CREDENTIALS_DIRECTORY` as read. When that variable is unset or empty it fails with `NO_CREDENTIALS_DIRECTORY`, and never falls back to another path.
- A missing, unreadable or empty file is `READ_FAILED`, naming the ref and the path, never the content.
- Files are read through `DriverContext.readFile`, `node:fs/promises` unless `loadKeys` is given another.
- The library never reads `process.env` implicitly.

### 2.3 Signer drivers [planned]

- `kms:projects/p/locations/l/keyRings/r/cryptoKeys/k[/cryptoKeyVersions/v]`, in `./identity/kms` (roadmap 2).
  - Accepts `alg` and `expect`.
  - Capabilities: secp256k1 and secp256r1; every purpose; not interactive; not deterministic; public key from the backend.
  - Upstream's factories take the client class, not an instance, and construct the client themselves. So the module injects the class.
  - Without a version, upstream resolves the primary version at load, so a key rotation changes the key. On `main`, `expect` makes that fail closed.
- `trezor:[user@host]`, in `./identity/trezor` (roadmap 3). It spawns the keeta-trezor-adapter CLI; the SLIP-0013 identity defaults to `keeta@keeta`.
  - Accepts `index`, `alg` and `expect`.
  - Capabilities: secp256r1; blocks only; interactive; deterministic; `publicKeyFrom: 'expect'`.

### 2.4 Format drivers [planned]

- A format driver turns a source's bytes into an account, under a `format` name. It declares its accepted shared params and its capabilities. Undefined capabilities mean the format holds only a public address.
- The format `kms-wrapped` (roadmap 2) reads upstream's KMS-wrapped JSON with `KeetaGCPKMSWrappedKeyPairFactory(...).lookupFromString`. The JSON carries its own key type and index, so the format accepts only `expect`.
- The format `privkey` takes `alg` and `expect`, but no `index`.

Adding format drivers adds `format` values to 1.2. The driver union gains a `format` kind, and none of the existing interfaces change.

### 2.5 Optional packages [planned]

- A driver that needs an optional package (`@google-cloud/secret-manager`, `@google-cloud/kms`) MUST live in its own subpath module.
- That module MUST import the package type-only and take the client from the caller.
- The root module MUST NOT resolve any optional package. [Holds trivially: there is no optional package yet.]

### 2.6 Content checks [implemented]

These checks run on the bytes read from a source, after trimming:

- `seed` is `^[0-9a-fA-F]{64}$`;
- `passphrase` is non-empty;
- `public` is a `keeta_` address.

Upstream also rejects a passphrase shorter than 60 bytes after its own processing (`ACCOUNT_PASSPHRASE_WEAK`). That is reported as `INVALID_CONTENT`, with upstream's code but not its message. No reason ever includes the content.

## 3. Schemas

### 3.1 Blocks [implemented]

The block union is `network() | publicAccount() | signer(...) | actor(...)`. A program combines blocks in `defineKeys({...}, { prefixes? })`.

| Block | Loads as | Takes |
|---|---|---|
| `network()` | `Network` (upstream's `main`, `staging`, `test`, `dev`) | a network name |
| `publicAccount()` | `GenericAccount`, with no signer property | a public ref |
| `signer({ purposes?, interactive?, algorithms? })` | `Account` | a signer ref |
| `actor({ signer, account?, feePayer? })` | `{ signer, account, network, feePayer? }` | see 3.2 |

- `signer()` defaults to `purposes: ['block']`, `interactive: 'forbid'` and every algorithm, the strict choice for an unattended service.
- Every top-level role is required until `optional` arrives.
- `loadKeys(spec, { env, drivers })` returns `Promise<Loaded<typeof spec>>`, a type derived from the spec.
- `defineKeys` MUST throw on any of these:
  - a role name that is not camelCase;
  - a prefix that is not SCREAMING_SNAKE_CASE;
  - a prefix for an undeclared role;
  - two roles that read the same variable.

Planned for roadmap 1:

- `keyring({ algorithms? })`, a `seed` or `passphrase` source with no `index` or `expect`, loads as a `Keyring` with `account(index, alg?)`;
- `list(block)` is comma-separated in the environment;
- `optional(block)`.

### 3.2 Actors [implemented]

| Option | Block | Variable | Meaning |
|---|---|---|---|
| `signer` | `signer(...)` | `PREFIX_SIGNER`, required | signs |
| (always) | | `PREFIX_NETWORK`, required | the network the actor is on |
| `account` | `publicAccount()` | `PREFIX_ACCOUNT`, may be unset | the account acted on. When unset, it is the signer's own |
| `feePayer` | `signer(...)`, constraining the fee payer's signer | `PREFIX_FEE_PAYER` and `PREFIX_FEE_ACCOUNT`, both may be unset | who pays the fees |

The fee payer resolves to `FeePayer { signer, account }`. When neither variable is set, it is `undefined`, and the actor pays its own fees.

| Set | `signer` | `account` |
|---|---|---|
| fee payer only | the fee payer | the fee payer's own account |
| fee account only | the actor's signer | the fee account |
| both | the fee payer | the fee account |

`createFeeBlockGenerator(feePayer, userClient)` returns upstream's `generateFeeBlock`. It calls `userClient.initBuilder(options).computeFeeBlock(staple, { account, signer })`, which is upstream's own default with the fee payer substituted.

### 3.3 The network of a signer [implemented]

- A signer in an actor is on the actor's network.
- A signer outside an actor is on the spec's single top-level `network()` role, if there is exactly one.
- Otherwise, or when the network value is invalid, the network is unknown, and the rules for `main` apply.

## 4. Fail-closed rules [implemented]

All static rules run before any secret is read, and all their issues are reported at once in one `KeyConfigError`. Load-time issues are then reported at once too.

1. A signerless position rejects a signer driver ref [`SIGNER_IN_PUBLIC_POSITION`].
2. A signerless position rejects a source ref with a secret format [`MATERIAL_IN_PUBLIC_POSITION`].
3. A signer position, the fee payer's included, rejects an address or a `#format=public` ref [`SIGNER_REQUIRED`].
4. `index` and `alg` are accepted only where the format or driver declares them [`PARAM_NOT_ALLOWED`].
5. On `main`, or on an unknown network, every signer MUST have `expect` [`EXPECT_REQUIRED`]. So MUST a signer whose capabilities say `publicKeyFrom: 'expect'`, on any network.
6. Key material where a ref is expected is an error [`KEY_MATERIAL_AS_REF`], and it is never shown. That means 64 hex digits, or 12 or more whitespace-separated words, in the whole value, the body, or a param name or value.
7. Capabilities are checked as the driver declares them, never by scheme name:
   - `interactive: 'forbid'` rejects an interactive signer [`INTERACTIVE_FORBIDDEN`];
   - every required purpose MUST be supported [`PURPOSE_UNSUPPORTED`];
   - the ref's possible algorithms MUST intersect the role's [`ALGORITHM_UNSUPPORTED`]. The possible algorithms are the driver's, narrowed by `alg` and by the algorithm of `expect`.
8. After loading:
   - a key that differs from its `expect` is an error [`EXPECT_MISMATCH`], which names the variable, the role and the derived public key;
   - a signer that loads an account that cannot sign [`SIGNER_REQUIRED`] is an error;
   - so is a signer that loads a key of a disallowed algorithm [`ALGORITHM_UNSUPPORTED`].
9. Bad content [`INVALID_CONTENT`], a failed read [`READ_FAILED`] and a missing credentials directory [`NO_CREDENTIALS_DIRECTORY`] are errors.
10. An empty string is unset.
11. A set variable under a declared prefix is an error [`UNKNOWN_VARIABLE`] unless a role or a ref reads it. That catches typos. "Under a prefix" means `PREFIX_*`, or the bare prefix of an actor.
12. Further errors:
    - a required value is missing [`MISSING_KEY`];
    - a network name is unknown [`INVALID_NETWORK`].
13. The library never reads `.env` files.
14. Errors contain only refs (canonical), variable names, roles and public keys.

`KeyConfigError` carries:

- `code`: the code of a single issue, or `INVALID_KEY_CONFIGURATION` when there are several;
- `issues: { code, location, role?, message }[]`.

`KeyConfigError.isInstance` recognizes the error by a type ID under a `Symbol.for` key, not by `instanceof`, so that it works across copies of the library.

## 5. Codecs

### 5.1 Environment [implemented]

- A role's prefix is its name in SCREAMING_SNAKE_CASE, with abbreviations kept whole:
  - `feeRecipients` becomes `FEE_RECIPIENTS`;
  - `accountID` becomes `ACCOUNT_ID`;
  - `baseURLPath` becomes `BASE_URL_PATH`.
- `defineKeys(..., { prefixes: { role: 'CUSTOM' } })` replaces the derived prefix.
- Variable names:
  - an actor `anchor` reads `ANCHOR_SIGNER`, `ANCHOR_ACCOUNT`, `ANCHOR_FEE_PAYER`, `ANCHOR_FEE_ACCOUNT` and `ANCHOR_NETWORK`, as far as it declares them;
  - any other role reads its prefix alone.
- Names are derived at run time from the spec. Deriving them at the type level is deferred.
- `decodeEnvironment(spec, env)` returns the set values keyed by field path (`anchor.signer`, `treasury`). It reads only declared variables, and an empty one is unset.
- `encodeEnvironment` is its inverse.
- Planned: a list is comma-separated, and an empty list is unset (roadmap 1).
- A role whose prefix would capture unrelated variables (`NODE_*`, `PATH_*`) SHOULD set a custom prefix.

### 5.2 Object / JSON [planned, roadmap 4]

- Shape: `{ "anchor": { "signer": "...", "network": "main" }, "deposits": ["keeta_..."] }`.
- An empty string or list is unset.
- An undeclared key is an error.

### 5.3 Command-line flags [planned, roadmap 4]

- Each flag is the variable name in lowercase, with `-` for `_`: `--anchor-signer`.
- A list flag may repeat.
- `--name value` and `--name=value` are both accepted.

## 6. Layers

Each layer is usable on its own.

1. Drivers [implemented]: the interfaces, `createDriverRegistry`, `environmentSource`, `fileSource` and `credentialSource`.
2. Single keys:
   - `parseKeyRef` and `formatKeyRef` [implemented];
   - `loadSigner`, `loadPublic` and `loadKeyring` [planned]. Each will check the static rules before it reads anything, and `loadSigner` with no network will apply the rules for `main`.
3. Schemas [implemented]:
   - the blocks and `defineKeys`;
   - the environment codec;
   - `loadKeys`;
   - `createFeeBlockGenerator`.

   `describeKeys` (refs and public keys only) is [planned].

Subpath exports: `.` and `./identity` [implemented]. `./identity/gsm`, `./identity/kms` and `./identity/trezor` arrive with their drivers.

## 7. Out of scope

- loading `.env` files;
- prompts;
- passkeys;
- collecting multisig signatures (a multisig address is just a public ref);
- on-chain permission checks;
- Rust.

## 8. Open questions

Not decided:

- Require `expect` on `test` too?
- Require a pinned `gsm` version on `main`? The same question applies to a `kms` key without `cryptoKeyVersions`.
- Keep `staging` and `dev`?

Raised by this draft:

- How should a keyring on `main` be pinned? It has no single public key.
- Should a single-value role's prefix, which is its whole variable name, count for the unknown-variable check?

## 9. Examples

```ts
import { actor, defineKeys, environmentSource, loadKeys, publicAccount, signer } from '@xescure/keeta-utils/identity';

const keys = defineKeys({
	anchor: actor({ signer: signer(), feePayer: signer() }),
	treasury: publicAccount()
});

const loaded = await loadKeys(keys, { env: process.env, drivers: [environmentSource()] });
loaded.anchor.signer;      // Account
loaded.anchor.feePayer;    // FeePayer | undefined
loaded.treasury;           // GenericAccount
```

```sh
ANCHOR_SIGNER='env:ANCHOR_SEED#index=0&expect=keeta_...'
ANCHOR_SEED=...            # 64 hex digits, never in a ref
ANCHOR_NETWORK=main
ANCHOR_FEE_ACCOUNT=keeta_...
TREASURY=keeta_...
```

More refs:

| Ref | Meaning | Status |
|---|---|---|
| `env:ANCHOR_SEED` | a secp256k1 key at index 0 of the seed in `$ANCHOR_SEED` | implemented |
| `env:COLD#format=passphrase&alg=ed25519&expect=keeta_...` | an Ed25519 key from a passphrase | implemented |
| `env:TREASURY_ADDRESS#format=public` | an address held in a variable | implemented |
| `cred:anchor#expect=keeta_...` | a seed in a systemd credential | implemented |
| `file:/run/secrets/anchor#format=passphrase` | a passphrase in a mounted secret | implemented |
| `kms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1#expect=keeta_...` | a GCP KMS key | planned |
| `gsm:projects/p/secrets/s/versions/3#format=kms-wrapped&expect=keeta_...` | a KMS-wrapped seed in Secret Manager | planned |
| `trezor:#index=2&expect=keeta_...` | a Trezor key that signs blocks after confirmation on the device | planned |
