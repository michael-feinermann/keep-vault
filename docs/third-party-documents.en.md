# Third-party documents

[Deutsch](third-party-documents.de.md) · [English](third-party-documents.en.md) · [Documentation index](README.en.md)

All first-party Keep Vault documentation is available in complete German and English editions. Bundled original documents from other projects are retained unchanged in their original language. These include licenses, copyright notices, reference publications, test vectors and documentation of the vendored source versions. They establish the provenance and terms of that version; the following guide is neither a replacement license nor a translation of cryptographic specifications.

The complete description of our local changes and pinned revisions is in [vendored-source provenance](../external/VENDOR-PROVENANCE.md). Its [German edition](../external/VENDOR-PROVENANCE.de.md) contains the same information. The complete description of password-analysis data is available in [German](password-model/README.de.md) and [English](password-model/README.en.md). Signed data and embedded original notices remain byte-identical.

| Collection | Original documents | Purpose |
|---|---|---|
| ML-DSA reference | [README](../external/ML-DSA-reference/README.md), [authors](../external/ML-DSA-reference/AUTHORS.md), [license](../external/ML-DSA-reference/LICENSE) | Documentation and license of the vendored reference code |
| Skein / Threefish | [NIST CD contents](../external/Skein-reference/NIST/CD/README/readme.txt), [KAT/MCT notes](../external/Skein-reference/NIST/CD/KAT_MCT/Readme.txt), [complete original collection](../external/Skein-reference/) | Original submission including papers, figures and reference test data |
| Crypto++ | [Readme](../external/cryptopp/Readme.txt), [license](../external/cryptopp/License.txt), [security](../external/cryptopp/Security.md), [test vectors](../external/cryptopp/TestVectors/Readme.txt), [original issue template](../external/cryptopp/.github/issue_template.md) | Documentation of the vendored Crypto++ version; local changes are described separately |
| Argon2id wrapper | [README](../external/argon2id/README.md), [license](../external/argon2id/LICENSE) | Origin and use of the vendored wrapper project |
| PHC Argon2 | [README](../external/phc-winner-argon2/README.md), [changelog](../external/phc-winner-argon2/CHANGELOG.md), [license](../external/phc-winner-argon2/LICENSE), [specification](../external/phc-winner-argon2/argon2-specs.pdf) | Reference implementation, original format and parameter description |
| ZPAQ | [Readme](../external/zpaq/readme.txt) | Original archiver documentation; Keep Vault adaptations are described in source provenance |
| Password-analysis data | [resource directory](../KalynaArchiver/Resources/PasswordModel/), [OPUS German](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-de.md), [OPUS English](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-en.md) | Unchanged data, complete `LICENSE-*` texts, attributions and manifest |
| Distributed notices | [German explanation](package-notices.de.md), [English explanation](package-notices.en.md) | First-party text explaining the complete license notices included with the package |

Commands, hashes, test inputs and original error messages remain unchanged in translated guides where they are technical evidence. An English error-message quotation in a German guide, or vice versa, is therefore not a missing translation section. Public test factors are synthetic test values only and must not be used for real archives.

Future changes to first-party guides are maintained in both language editions. Changes to vendored sources, data or legal notices instead require the checks specified in the respective build and provenance document. A documentation translation changes no executable and does not certify a new cryptographic review.
