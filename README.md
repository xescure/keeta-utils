# Keeta Utils

`@xescure/keeta-utils/identity` is how a Keeta program gets its keys. A program declares its roles, and `loadKeys` reads key references from the environment and returns upstream `Account`s.
Every rule is checked before any secret is read, every error is reported at once, and errors never show key material.
It is a thin layer over `@keetanetwork/keetanet-client`, which does the key derivation and signing.

The design, the parts this version implements, and the roadmap are in [SPEC.md](SPEC.md). `nix develop` gives Node 24 and make. `make -j check` type-checks and tests, and `nix flake check` runs the same check offline.
