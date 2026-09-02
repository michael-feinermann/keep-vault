# Vendored third-party sources

These directories are vendored **with local modifications** required for the macOS port.
The upstream git metadata is intentionally not tracked; provenance is recorded here.

Generated: 2026-08-15T15:46:48Z

## Kalyna-512/512
- Production implementation: Crypto++ `CRYPTOPP_8_9_0`, covered by the
  Crypto++ provenance and Boost Software License section below.
- The earlier `Roman-Oliynykov/Kalyna-reference` snapshot and Keep Vault's
  derived table adapter were removed before v12: the pinned upstream tree did
  not contain a licence grant, so neither its source nor a derived binary is
  built, bundled or distributed.
- The v12 adapter exports v12-specific symbols only. An official
  DSTU 7624:2014 vector, an independent Bouncy Castle differential matrix,
  scalar-versus-parallel equivalence and full container KATs gate the change.

## Skein-reference
- Upstream: the Skein 1.3 NIST submission CD reference implementation
  documented by its bundled `NIST/CD/README/readme.txt`; specification:
  https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf
- Local changes (line-ending noise excluded): two hardening changes in
  `NIST/CD/Reference_Implementation/skein.c` and `skein_block.c`, marked with
  Keep Vault comments. Each 256-, 512-, and 1024-bit initialization helper
  erases its local configuration/key-derivation union, each final/output helper
  erases its local chaining-state copy, and each block helper erases its
  transient tweak schedule, key schedule, working state, and message words
  through a volatile byte loop before returning. This does not alter Skein or
  Threefish outputs; it prevents key-derived stack residues from surviving a
  one-shot MAC/KDF operation. Official Skein KATs and the independent Bouncy
  Castle differential gate cover output equivalence.

## cryptopp
- Upstream: https://github.com/weidai11/cryptopp
- Release tag: `CRYPTOPP_8_9_0`
- Source archive: https://github.com/weidai11/cryptopp/archive/refs/tags/CRYPTOPP_8_9_0.tar.gz
- Archive SHA-256: `ab5174b9b5c6236588e15a1aa1aaecb6658cdbe09501c7981ac8db276a24d9ab`
- Local changes (line-ending noise excluded): one, in `cryptopp/cpu.cpp`, marked
  in place with `KEEP VAULT LOCAL CHANGE`. See "Local change: Apple silicon
  feature detection" below. Every other file is the upstream release verbatim.
- Licence: Boost Software License 1.0 for the compilation; the individual
  algorithm files are placed in the public domain by their authors. See
  `cryptopp/License.txt`.

### Local change: Apple silicon feature detection

`AppleMachineInfo` in `cpu.cpp` decides which instruction set an arm64 Mac has
by comparing `machdep.cpu.brand_string` to the literal string `"Apple M1"`.
Anything else takes the unknown branch and is reported as plain ARMv8. Every
call site in that file that answers for AES, PMULL, SHA-1, SHA-2 and CRC32 asks
for ARMv8.2, so on an M2, M3, M4 or M5 — and on an M1 Pro, whose brand string is
not `"Apple M1"` — Crypto++ reports those instructions absent and selects its
portable C++ paths on hardware that implements all of them. Measured on an
M5: AES-256-CTR ran at 1876 MB/s instead of 8862 MB/s.

The change asks the kernel instead of the marketing name:
`hw.optional.arm.FEAT_AES`, `FEAT_PMULL` and `FEAT_SHA256` via `sysctlbyname`.
It is conservative in both directions — a core without them is reported as
ARMv8, exactly as the old default did, and ARMv8.3 is never claimed, which
nothing in the file queries. A kernel that does not publish those keys fails
the lookup, which is the same answer as "not present", so the previous
behaviour is what remains.

Nothing outside CPU capability detection is touched, and no algorithm,
constant or code path is altered: which implementation of a cipher runs
changes, what it computes does not. The build gate that holds this is
`tools/Build-Native-macOS.sh` plus the differential harness — every cipher
compared before and after across 448 key, nonce and length combinations with no
ciphertext difference, and `KeepVaultMac/Packaging/NativeKats.c` passing on both
slices.

Upstream carries the same defect in `CRYPTOPP_8_9_0`, the current release. To
drop this change, take a release whose `AppleMachineInfo` no longer decides the
instruction set from the brand string.

Vendored whole rather than file by file. The algorithm sources cannot be taken
out on their own: `rijndael.cpp` and its siblings all depend on `cryptlib.h`,
`config.h`, `secblock.h` and `misc.h`, so a hand-picked subset would not
compile and would have to be maintained by hand at every update. Only the files
listed below are actually built; the rest is carried so the release is the
upstream release and its checksum still means something.

Used for:
- **MARS-448** (`mars.cpp`), **SHACAL-2-512** (`shacal2.cpp`),
  **ChaCha20-Poly1305** (`chachapoly.cpp`, `chacha.cpp`) and the
  **AES-256 reference fallback** (`rijndael.cpp`) — primitives with no
  reference implementation in this repository before.
- **SHA-512** (`sha.cpp`) for the second Argon2id round, which needs a
  reference to check the platform implementation against; only SHA3-512 had one.
- The **production implementation** of Kalyna-512/512 (`kalyna.cpp`) and an
  independent test implementation of Threefish-1024 (`threefish.cpp`). Kalyna
  is held against official DSTU 7624:2014 vectors and Bouncy Castle's separate
  managed implementation. Threefish continues to run on the Skein reference
  source above and uses Crypto++ as its independent differential oracle.

## argon2id
- Upstream: https://github.com/alexedwards/argon2id
- Base commit: `493d7dead70e0797a6cc1a189d96f7c115e073e8`
- Local changes (line-ending noise excluded): none, CRLF normalization only

## phc-winner-argon2
- Upstream: https://github.com/P-H-C/phc-winner-argon2
- Base commit: `f57e61e19229e23c4445b85494dbf7c07de721cb`
- Local changes (line-ending noise excluded): 1 file changed, 16 insertions(+)

## zpaq
- Upstream: https://github.com/zpaq/zpaq
- Base commit: `9ab539f644e364f0d92e2918b90ce2534c75653f`
- Local changes (line-ending noise excluded): 3 files changed, 2213 insertions(+), 366 deletions(-)
  (`zpaq.cpp` +2181/-350, `libzpaq.cpp` +8/-8, `libzpaq.h` +24/-8).

Every first-party native build verifies the reviewed vendor-source inventory in
`NATIVE_SOURCE_SHA256SUMS` before compiling. The manifest also prevents a newly
dropped Crypto++ translation unit from entering the build through a wildcard.
