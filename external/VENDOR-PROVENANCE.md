# Vendored third-party sources

These directories are vendored **with local modifications** required for the macOS port.
The upstream git metadata is intentionally not tracked; provenance is recorded here.

Generated: 2026-08-15T15:46:48Z

## Kalyna-reference
- Upstream: https://github.com/Roman-Oliynykov/Kalyna-reference
- Base commit: `22eafbcaf6635dc5e1f8a734b1f7c5ab84b5a5ea`
- Local changes (line-ending noise excluded): none, CRLF normalization only

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
- An **independent second implementation** of Kalyna-512/512 (`kalyna.cpp`) and
  Threefish-1024 (`threefish.cpp`), used in tests only. Both ciphers keep
  running on their original reference code — `Kalyna-reference` and
  `Skein-reference` above — and Crypto++ is there to disagree with them if one
  of the two is wrong. Two implementations that agree on the official test
  vectors is worth more for an archive format than one that merely compiles.

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
- Local changes (line-ending noise excluded): 3 files changed, 604 insertions(+), 234 deletions(-)

