# Dependency upgrade — 4 November 2026

The desktop's 16 direct and development registry dependencies were checked
against the official crates.io API, including incompatible major releases.
`max_stable_version` and non-yanked version records were used; the most recently
published maintenance release is not always the highest stable version
(`rfd` 0.16.1 was published after 0.17.2, which remains the highest stable).
No direct dependency currently requires a prerelease.

| Dependency | Previous lock | Current direct version | Result |
| --- | --- | --- | --- |
| `iced` | 0.14.0 | 0.14.0 | Already latest stable |
| `image` | 0.25.10 | 0.25.10 | Already latest stable |
| `hex` | 0.4.3 | 0.4.3 | Already latest stable |
| `uuid` | 1.26.1 | 1.29.0 | Updated |
| `frost-ed25519` | 3.0.0 | 3.0.0 | Already latest stable |
| `frost-secp256k1-tr` | 3.0.0 | 3.0.0 | Already latest stable |
| `tokio` | 1.53.1 | 1.54.1 | Updated |
| `anyhow` | 1.0.104 | 1.0.104 | Already latest stable |
| `tracing` | 0.1.44 | 0.1.44 | Already latest stable |
| `tracing-subscriber` | 0.3.23 | 0.3.23 | Already latest stable |
| `rfd` | 0.17.2 | 0.17.2 | Already latest stable |
| `async-trait` | 0.1.92 | 0.1.92 | Already latest stable |
| `chrono` | 0.4.45 | 0.4.45 | Already latest stable |
| `iced_test` | 0.14.0 | 0.14.0 | Already latest stable |
| `serde_json` | 1.0.151 | 1.0.154 | Updated |
| `k256` | 0.14.0 | 0.14.0 | Already latest stable |

Broad manifest ranges now state the current stable release as their minimum
compatible version. All registry resolutions were passed to `cargo update`,
while the three internal Git dependencies remained at the committed engine
revision `63336972abc60b5cedc2026c039efcdf8e4f2dd8`.

## Transitive coverage and upstream constraints

The registry audit covers all 840 unique registry crate names in the final
lockfile. Updating all 962 previous registry resolutions changed the version
sets of 258 crate names; the resulting lock contains 959 registry resolutions.
Of those, 682 are the latest stable, 274 are older copies on incompatible
upstream version lines, and three belong to the existing prerelease ECDSA
family. No remaining older stable copy is merely an available patch/minor
update within the same compatible version line.

The engine pins `cggmp24`, `cggmp24-keygen` and `paillier-zk` to exactly
`0.7.0-alpha.3`. The driver is already its latest prerelease; keygen and
Paillier have alpha.4 releases, but those cannot be selected through the
engine's exact requirements and are incompatible with the current driver
family. This desktop upgrade does not alter engine cryptography or install
unconditional dependency overrides.

The old copies below remain present alongside newer copies. Updating a parallel
copy does not remove the affected version from the dependency graph.

| Residual advisory | Actual dependency chain | Patched release / current latest | Blocking requirement |
| --- | --- | --- | --- |
| [crypto-bigint timing variability](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) | Engine/FROST/ECDSA dependencies → `elliptic-curve 0.13.8` → `crypto-bigint 0.5.5` | Fixed in 0.7.6; parallel 0.7.10 is updated | `elliptic-curve` requires `crypto-bigint ^0.5`; migrating its public crypto types requires upstream changes. |
| [lru panic-safety use-after-free](https://rustsec.org/advisories/RUSTSEC-2026-0253.html) | Latest Iced 0.14 → `iced_wgpu 0.14.0` → latest `cryoglyph 0.1.0` → `lru 0.16.4` | Fixed in 0.18.2; parallel 0.18.5 is present; latest is 0.19.0 | `cryoglyph` requires `lru ^0.16`. Neither latest stable Iced nor cryoglyph permits the fixed line. |
| [serde_with serialization panic](https://github.com/jonasbb/serde_with/security/advisories/GHSA-7gcf-g7xr-8hxj) | `cggmp24` / `cggmp24-keygen` alpha.3, `generic-ec 0.4.5`, `key-share 0.6.1` → `serde_with 2.3.3` | Fixed in 3.21.0; parallel 3.24.0 is updated | Each listed parent requires `serde_with ^2`; a compatible lock refresh cannot choose 3.x. |

The `lru` advisory requires a panicking key destructor, unwinding and subsequent
cache operations; the `serde_with` advisory concerns `KeyValueMap`
serialization. These conditions are not a claim of exploitability in the
wallet. No exploitability exemption or clean security-audit claim is made.
The registry/OSV review also reports unmaintained transitive copies of
`atomic-polyfill`, `bincode`, `paste`, `rustybuzz`, `ttf-parser`, `zbus_names`,
`zvariant` and `zvariant_derive`; these notices remain distinct from the three
security defects above.

## Development environment

All Nix flake inputs were refreshed to their current upstream references:
`nixpkgs ea9e3ef341e11c193537f674f821a99f9f436729`,
`flake-parts ea2630b7470978622c7689a1ff75d2b389175399`, and
`nixpkgs-lib 7851ba61fd862b277cb6a9cef37394bc18bb94e4`.
The development toolchain moves from Rust 1.98.1 / Cargo 1.98.0 to
Rust 1.99.0 / Cargo 1.99.0. Deprecated Nix platform and X11 attribute aliases
were replaced with their current names; platform behavior is unchanged.
The workflow uses the independently verified current release tags for
`actions/checkout` and `cachix/install-nix-action`.

## Validation

Verified with the committed upgraded dependency graph and Rust 1.99.0:

- `cargo check --locked`: passed (4 minutes 43 seconds).
- `cargo fmt --check`: passed.
- `cargo test --locked`: 51 passed, zero failed, one ignored (28.91 seconds).
- `cargo clippy --locked --all-targets -- -D warnings`: passed.

The optimized artifact, ignored three-adapter integration result, actual
isolated-window screenshots and remote CI results are recorded on the
associated pull request after they complete; they are not implied by the
checks above. Reproduce those additional gates with:

```sh
nix develop --command cargo build --locked --release
nix develop --command cargo test --locked three_devices_create_a_wallet_and_sign -- --ignored
```

The integration uses three real runner instances and a private local signal
server, with explicitly insecure test prime fixtures. It creates a 2-of-3
wallet, signs Ethereum account 1 with independent address recovery, and
exports/imports an encrypted FROST share. It does not represent a fresh-prime
live wallet, physical device or chain transaction.

The complete per-resolution old/new and parent-requirement audit, official API
responses, OSV findings and compiler logs are retained outside the repository
for review; this note does not claim every upstream dependency can use its
latest incompatible release without changes to its owner.
