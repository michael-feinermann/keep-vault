# Dokumente von Drittanbietern

[Deutsch](third-party-documents.de.md) · [English](third-party-documents.en.md) · [Dokumentationsverzeichnis](README.md)

Die selbst verfasste Keep-Vault-Dokumentation liegt vollständig auf Deutsch und Englisch vor. Mitgelieferte Originaldokumente anderer Projekte bleiben in ihrer Originalsprache und unverändert erhalten. Dazu gehören Lizenztexte, Copyright-Hinweise, Referenzpublikationen, Testvektoren und die Dokumentation der eingebundenen Quellstände. Sie belegen Herkunft und Bedingungen des jeweiligen Stands; die folgende Übersicht ist keine Ersatzlizenz und keine Übersetzung kryptografischer Spezifikationen.

Die vollständige Beschreibung unserer lokalen Änderungen und festgelegten Revisionen findest du unter [Herkunft der eingebundenen Quellen](../external/VENDOR-PROVENANCE.de.md). Deren [englische Fassung](../external/VENDOR-PROVENANCE.md) enthält dieselben Angaben. Die vollständige Beschreibung der Passwortanalysedaten steht auf [Deutsch](password-model/README.de.md) und [Englisch](password-model/README.en.md) bereit. Die signierten Daten und eingebetteten Originalhinweise bleiben bytegleich.

| Bestand | Originaldokumente | Zweck |
|---|---|---|
| ML-DSA-Referenz | [README](../external/ML-DSA-reference/README.md), [Autoren](../external/ML-DSA-reference/AUTHORS.md), [Lizenz](../external/ML-DSA-reference/LICENSE) | Dokumentation und Lizenz des eingebundenen Referenzcodes |
| Skein / Threefish | [NIST-CD-Inhalt](../external/Skein-reference/NIST/CD/README/readme.txt), [KAT-/MCT-Hinweise](../external/Skein-reference/NIST/CD/KAT_MCT/Readme.txt), [vollständiger Originalbestand](../external/Skein-reference/) | Originaleinreichung einschließlich Fachartikeln, Abbildungen und Referenztestdaten |
| Crypto++ | [Readme](../external/cryptopp/Readme.txt), [Lizenz](../external/cryptopp/License.txt), [Sicherheit](../external/cryptopp/Security.md), [Testvektoren](../external/cryptopp/TestVectors/Readme.txt), [ursprüngliche Issue-Vorlage](../external/cryptopp/.github/issue_template.md) | Dokumentation des eingebundenen Crypto++-Stands; lokale Änderungen sind separat beschrieben |
| Argon2id-Wrapper | [README](../external/argon2id/README.md), [Lizenz](../external/argon2id/LICENSE) | Herkunft und Nutzung des eingebundenen Wrapperprojekts |
| PHC Argon2 | [README](../external/phc-winner-argon2/README.md), [Änderungsverlauf](../external/phc-winner-argon2/CHANGELOG.md), [Lizenz](../external/phc-winner-argon2/LICENSE), [Spezifikation](../external/phc-winner-argon2/argon2-specs.pdf) | Referenzimplementierung, Originalformat und Parameterbeschreibung |
| ZPAQ | [Readme](../external/zpaq/readme.txt) | Originaldokumentation der Archivierungsbibliothek; Keep-Vault-Anpassungen stehen in der Quellenherkunft |
| Passwortanalysedaten | [Ressourcenverzeichnis](../KalynaArchiver/Resources/PasswordModel/), [OPUS Deutsch](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-de.md), [OPUS Englisch](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-en.md) | Unveränderte Daten, vollständige `LICENSE-*`-Texte, Attributionen und Manifest |
| Ausgelieferte Hinweise | [deutsche Erläuterung](package-notices.de.md), [englische Erläuterung](package-notices.en.md) | Projekttexte zu den im Paket beigefügten vollständigen Lizenzhinweisen |

Befehle, Hashes, Testeingaben und originale Fehlermeldungen bleiben auch in übersetzten Anleitungen unverändert, soweit sie technische Nachweise sind. Ein englisches Fehlermeldungszitat in einer deutschen Anleitung oder umgekehrt ist deshalb kein fehlender Übersetzungsabschnitt. Öffentliche Testfaktoren sind ausschließlich synthetische Prüfwerte und dürfen nicht für echte Archive verwendet werden.

Künftige Änderungen an eigenen Anleitungen werden in beiden Sprachfassungen nachgeführt. Änderungen an eingebundenen Quellen, Daten oder rechtlichen Hinweisen benötigen dagegen die im jeweiligen Build- und Herkunftsdokument festgelegten Prüfungen. Eine reine Dokumentationsübersetzung aktualisiert keine Programmdatei und bestätigt keine neue kryptografische Prüfung.
