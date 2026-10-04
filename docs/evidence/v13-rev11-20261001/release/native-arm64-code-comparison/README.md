# ARM64-Ciphervergleich Build 14 / Build 15

Reine öffentliche Binäranalyse. Keine Ausführung von Ciphercode, kein Benchmark, kein Build und keine Änderung an Originalen oder installierten Dateien.

Ergebnis: 8 von 8 ARM64-Cipherbibliotheken sind nach dem Entfernen der Apple-Code-Signaturen aus exklusiven Scratchkopien vollständig byteidentisch. Das gilt für die gesamte verbleibende Mach-O-Datei, sämtliche ausgewerteten Sections und alle verbleibenden Load Commands. Die signierten Universaldateien sowie ihre signierten ARM64-Slices unterscheiden sich in allen acht Fällen. Der Vergleich belegt somit identische Cipherbytes nach der Signaturentfernung; er liefert keinen Nachweis zur Ursache der gemessenen Laufzeitabweichung.

Die historischen Dateien stammen aus `historical-control-536d7c2/harness/Native`, die aktuellen aus `resume-harness/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/Native`. Jede Originaldatei wurde vor der Ableitung gegen das jeweilige vorhandene Harness-Manifest geprüft. SHA-256, Größe, Geräte-/Inodekennung, mtime, ctime und Modus aller 16 Originaldateien sowie der beiden Manifeste stimmen vor und nach der Prüfung exakt überein.

Zeitraum UTC: 2026-10-01T11:13:53.587816+00:00 bis 2026-10-01T11:13:54.057756+00:00.

| Bibliothek | SHA-256 des identischen unsignierten ARM64-Slices |
| --- | --- |
| `libaes_ref.dylib` | `6fef93bbb92cac8fc7a09bb0d69e93c029ddd6646ac8522509990e3c1f8ce337` |
| `libkalyna_v13.dylib` | `8cb39f8c4a7ec5c1b36b983a0c525d2e2a1acedb3e8ac733f2bd8a2cd93dca48` |
| `libthreefish_ref.dylib` | `0dc9818ceaf1ba2bde3422ad5d61e8f32cc9742af589f8a943a471f638187979` |
| `libxchachapoly_v13.dylib` | `bdee237609d0eda38c553fe8aa5f11fe8d79307b36a08582473ba29f5249ec2c` |
| `libmars_ref.dylib` | `6aa402ff949834ca76c9337f266350631078bdce7f2a982a08f0b83a49fea988` |
| `libshacal2_ref.dylib` | `635f1785462ef208268923d5f0a3a142cb68de141647cf53b8e614ca766b467f` |
| `libcamellia_v13.dylib` | `7a19bb1b6220ecc1869b4db04f09ea61306a37bdae9840660843f9aa2775c35f` |
| `libserpent_v13.dylib` | `00eee82914e86a006ebbcb4b784f8d15396d46be25deea7c85bd4ce914d6c76e` |

Die vollständigen Original-/Ableitungshashes, Manifestbindungen, Kommandos samt Exitcodes und die Mach-O-Auswertung stehen in `comparison.json`. `compare.py` erzeugt zuerst separate vollständige Kopien, extrahiert daraus mit `/usr/bin/lipo -thin arm64` die Slices und entfernt mit `/usr/bin/codesign --remove-signature` ausschließlich auf einer weiteren Scratchkopie die Signatur. Es verwendet keine Signierschlüssel.

SHA-256 `comparison.json`: `ad6a28c8b2f74922fae5c7f097b58d9bb9a2f9cade6d161a596f66699fe865f9`.
SHA-256 `compare.py`: `e050ebd346e6edeec70a38a78785ba03c6f9085c43592cffc12f225e1103a575`.

Grenze: Dieser Vergleich bestätigt die Binäridentität der bereitgestellten Cipherdateien beider Harnesses. Er setzt die Messungen nicht gleich und ersetzt weder einen Performance-PASS noch eine Prüfung der sonstigen Managed-/Ressourcenverwaltung.
