# Native and provisioning evidence, 2026-09-21

The JSON files record local macOS arm64 runs with public synthetic inputs.
`xchacha-interop-arm64.json` reports 33,545 checks, 132 boundary cases and
10,000 deterministic randomized records against pinned libsodium, Go and
Crypto++ references. The native binary hash identifies the measured development
artifact; it is not an installed-release attestation. The later `/kv13-`
snapshot-name change does not alter the cryptographic algorithm, but the final
release build still needs its own test run and hash.

`xchacha-initialization.json` records the accepted removal of redundant
ChaCha initialization. `ctr-reuse-rejected.json` records the rejected broad
key-schedule reuse candidate. The reference fixtures and hashes are under
`native/tests`; no reference dependency ships in the application.

The native C KAT executable passed on macOS arm64 and on the x86_64 slice via
Rosetta. The latter is macOS x64 execution, not a Windows result.

The provisioning changes were reviewed without reading actual key material.
The following managed groups passed on the current source:

* `packaging.private-directory-lease`: extended file/directory ACL rejection,
  mode changes, directory replacement and refusal before creation in the
  substituted directory.
* `packaging.usb-wrapping-key-input`: existing malformed, noncanonical,
  linked-file, mutation and private-permission checks.
* `packaging.hybrid-key-separation`: full existing independent RSA/ML-DSA
  wrapping-key and envelope regression group; its machine-readable result is
  included here.

Both the HybridSigner and macOS test project built with zero warnings and zero
errors. The key-directory lease is retained across provisioning and passed
through envelope writes into the descriptor-bound create/publish path. All
private reads, new files and published files reject extended ACLs and require
ownership enforcement; the provisioning directory requires current-user mode
0700. macOS PFX loading is guarded by the existing isolated temporary-keychain
flow. Ordinary FileStream write buffering was removed. Failed provisioning
writes wipe their held descriptor and unlink only a still-owned namespace
entry, preserving substituted objects.

These tests do not claim complete erasure of Bouncy Castle internals, operating
system key objects, registers or copy-on-write storage. No actual release-key
regeneration was performed as part of this review.
