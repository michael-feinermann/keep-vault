# Keep Vault 5.0.2: password and PIN contract for container v12

[Deutsch](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) | English

This specification supplements the existing v12 contract. The macOS app receives
marketing version 5.0.2 and build number 13. Container v12 and KPAR2 v4 remain
unchanged. The separately verified version 5.0.1 is preserved in tag `v5.0.1`.
The final audit report for 5.0.2 must demonstrate implementation of this
contract. A specification alone does not confirm that tests have passed.

## Archiving and restoration

The password and PIN are chosen by the user. The two independent generated
key-sheet factors A and B retain their existing checks. There is no password
or PIN generator and no exception for claims that an input originated randomly.

All existing and additional selection and strength rules apply exclusively
when creating an archive. The shared container service checks the final values
before mutating output. A GUI precheck does not replace this check. Changes to
the password, PIN or local date must not reuse a stale positive pair check.

Neither old nor new selection rules apply during extraction, listing,
authentication and repair: no 24-character minimum, no 256-character password
limit, no 6-to-16-digit PIN limit, no composition rules, blocklists, pattern,
date, substring or model evaluation. These paths must not require the relevant
model resources to be loaded or evaluated. Even cryptographically correct
empty or short values are not blocked because of their quality.

Technical processing remains necessary: non-null strings, ASCII digits for
the PIN, unchanged UTF-8 encoding of the password, factor-format syntax, safe
resource allocation and cryptographic verification. The password and PIN each
have a separate technical upper limit of 1,048,576 UTF-16 code units. This
limit protects allocations; it is not an acceptance rule for new secrets.
Leading zeros, spaces in the password and its original Unicode representation
are preserved. No normalization, trimming or case conversion changes KDF bytes.

The existing header field
`UserPassword24to256+PIN6to16+GeneratedHex1024x2` remains byte-identical as a
v12 protocol identifier. Its name describes the creation profile and must not
be used to repeat quality checks when reading. A model update changes neither
magic, version, header order, domains, length prefixes, salts, nonces, roles
nor the authentication and KDF procedures.

## Unchanged password rules at creation

The rules remain 24 to 256 UTF-16 code units, at least three character classes,
twelve distinct `char` values, twelve non-hex occurrences, at most seven
consecutive ASCII hex characters, no control characters and no invalid UTF-16
sequences. Password confirmation and factor comparisons are retained. The two
generated factors must be different.

The existing calculation with the factor 0.70 and all deductions is retained.
The final value is the minimum of this existing value and all applicable
additional, fully specified model values. An existing rejection must never
become an acceptance. The threshold remains
`MinimumConservativeEntropyBits = 128.0`.

Additional models consider the complete input, including word sequences,
ambiguous segmentation, concatenation, compounds, inflection, leetspeak,
spelling variants, names, keyboard walks, repetition, dates/years, suffixes and
unknown residual parts. Word matches are not counted more than once as
additional strength. A single dictionary word alone does not block a password.
Failure to recognize words does not prove random origin.

All data is bundled offline, versioned, checked for counts, duplicates and
hashes, and authenticated by the signed app. This applies from the first launch.
Missing or damaged data prevents a positive archiving decision and does not
trigger a network replacement. Restoration remains available when data is
faulty. Runtime updates are not a prerequisite and must not replace the
verified data without verification. This separation does not override the app
integrity check. A tampered signed application may still be rejected entirely
at startup; the reader itself does not need model data in an intact app.

The fixed recognition datasets are:

| Dataset | Size | Treatment |
| --- | ---: | --- |
| EFF English, long list | 7,776 | List space with `log2(7776)` per freely combinable word |
| dys2p German, based on EFF | 7,776 | Independent German source, not a purported German EFF edition |
| BIP39 English | 2,048 | Original order, word indices and checksum preserved |

Valid complete BIP39 sequences of 12, 15, 18, 21 or 24 words have upper limits
of 128, 160, 192, 224 or 256 original entropy bits, respectively. Checksum bits
are not added. Invalid word sequences do not receive valid mnemonic status.
Variants and additional characters must be evaluated as a complete construction.
No wallet seed is calculated. These spaces do not demonstrate the entropy of
human selection.

Additional data, fixed versions, licenses, transformations and model limits
are documented with the [bundled model data](../KalynaArchiver/Resources/PasswordModel/README.md).
An exact match in the selected local password blocklist is rejected. The
limited dataset must not be represented as a complete HIBP snapshot. No PIN,
password, input hash or personal parts of an input leave the process for these
checks.

## Unchanged and additional PIN rules at creation

The existing rules remain six to sixteen ASCII digits, at least four distinct
digits, confirmation, the complete existing blocklist and all rules for
triplets, sequences, keypad patterns, repetition and double groups. The
additional models can only cause further rejections.

The entire PIN must not be a contiguous literal substring of the raw password.
Leading zeros count. Digits are neither separated nor joined for this rule.
The final pair check requires both values; an isolated PIN precheck must not
claim approval of the pair.

The PIN must not equal today's local calendar date in `DDMMYY`, `DDMMYYYY`,
`MMDDYY` or `MMDDYYYY`. On 06.09.2026 these are `060926`, `06092026`, `090626`
and `09062026`. The rule uses equality of the entire value and is reevaluated
immediately during the final creation check. The device time zone determines
the date; without network time, an incorrect local clock can affect it.
Duplicate format values are the same blocked value.

Further calendar checks validate real days, including leap years. The versioned
reference year is 2026, and the initial four-digit range is 1900 to 2056. It is
independent of the current local date. Additional numeric patterns must not
undo earlier rejections. A date segment within a longer PIN is not a match
under today's date-equality rule.

The 17-to-30-bit thresholds and HIBP counts of 10 or 20 discussed in the
source document are uncalibrated design values. They are not demonstrated
security limits. Without independent calibration, no corresponding empirical
guess rank or guaranteed minimum protection is claimed.

## Display and version

The marketing version, for example `Version 5.0.2`, appears directly beneath
the German or English subtitle, using the same versioning as the build. The
version line and wrapped subtitle must remain readable at the smallest
supported window size.

Display and decision use the same corrected model value. The display rounds
down to whole model bits, so that, for example, 127.9 does not appear as 128.
The text calls it an estimate. Neither estimates nor wordlist spaces are
presented as measured source entropy or decryption time. The detailed help
explains coverage and uncertainty.

## Attack path and limits of evidence

Both v12 credential branches depend on the password, PIN and both generated
factors. Normal suites require two Argon2id calls, Paranoia four with a fully
dependent second round. The app executes them sequentially with bounded memory.
An attacker can parallelize independent branches of the same round using
additional memory.

After the complete KDF, a candidate can be checked using small authenticated
KPAR2 metadata or suitable container tags/chunks. The attacker does not need
to execute the entire GUI archiving, recovery and extraction workflow for this.
GUI benchmark times are not a lower bound on the attacker's costs. Publicly
stored fields and derived PMI receive no bonus as an independent secret.
Password and PIN model values are not added together; both are human-chosen
knowledge secrets.

## Cross-platform acceptance

At least the following evidence is required before completion:

1. All previous negative cases remain rejected; every model corpus case
   satisfies `Hneu <= Halt`. The two documented Sommer-Wiese examples are
   corrected to below the unchanged 128-bit threshold, including concatenation,
   spelling variants and typical appendages.
2. Wordlist counts, duplicates, normalization variants, independent BIP39
   checksum vectors for all five lengths, negative cases and overlapping
   segmentations are checked. 256-character boundary cases remain time-bounded.
3. PIN pair rules at the start, middle and end, leading zeros, separated digits,
   date changes, time zones, leap years and supplementary patterns have positive
   and negative counterchecks.
4. Static synthetic v12 archives with cryptographically correct inputs that
   would be prohibited for new creation are extracted, listed and checked/repaired
   through KPAR2. A deliberately failing model call must be unreachable from
   these paths. KDF intermediate values demonstrate unchanged input bytes.
5. Missing and damaged data prevent a positive archiving check; no network
   query replaces it. Complete archiving and extraction must pass in a fresh
   process with the external network blocked, including the selection check and
   all required local model data without a preparatory model download. Network
   state and positive controls before and after the complete run are recorded.
   The actual GUI is tested independently for archiving and extraction; first
   launch, models and GUI selection checks without a network are demonstrated
   separately. A core test with frozen production sources and installed native
   bytes must be identified as such and not as a complete offline GUI run.
6. Complete macOS testing, the DE/EN GUI, identical installed/signed artifacts
   and all v12 release gates are rerun for 5.0.2. Windows must later independently
   confirm the same model resources, input bytes, test vectors and rules on real
   Windows hardware.

This revision clarifies the evidence strategy. The user document
“Keep Vault: Sicherheitsmodell für PINs und Passwörter” (Keep Vault: security
model for PINs and passwords) of 6 September 2026 requires fully offline
operation in section 3.2 and complete workflows with the network blocked in
section 6. It does not mandate a single continuous GUI test for this purpose.
The separate offline and GUI checks must be bound to the same frozen production
sources, models and signed native bytes. The earlier wording of this contract
coupled the two testing methods more closely than the product requirement;
this clarification changes no function, selection rule or offline obligation.
An incomplete offline run must not be counted as passed on the basis of GUI
evidence.

The existing deletion rules remain unchanged: only the specific original files
that were archived and compared again are deleted. Their original directories
remain in place. A quality change does not expand this destructive scope.
