# Öffentliches REV12-Stageprofil, 3. Oktober 2026

Dieses Paket archiviert den bestandenen Entwicklungsworker `performance.rev12-stage-profile` des eingefrorenen Build `20261003T102259Z`, Lauf `frozen-stage-20261003T103049Z-c7dfcc2c`. Es wurde als lokale öffentliche Prüfevidenz erstellt und ist keine Veröffentlichung oder Produktfreigabe.

## Umfang

Ein verwalteter Release-Testharness ruft die tatsächlichen produktiven nativen Cipheradapter auf macOS 27.0.1, Apple M5, arm64 auf. Die nativen Bibliotheken sind die unveränderten signierten Bytes des installierten Build 15. Der aktuelle AES-Provider ist ArmV8. Quell-HEAD ist `b41144e191d743aa4474cb3a9fe1e5c1c7c567ba`; uncommittete Änderungen gehören zum getesteten Stand, deshalb bindet der Ausführungsbeleg zusätzlich das vollständige Quellinventar.

Gemessen sind zehn Optionen: acht Einzelprimitive sowie Standard- und Paranoiakaskade, jeweils bei tatsächlichen Workergrants 1, 4 und 10. Jeder der 30 Fälle verarbeitet einen öffentlichen 256-MiB-Payload in 16-MiB-Chunks. Auf einen Warm-up je Variante folgen fünf Defaultläufe und fünf Läufe mit eingeschaltetem Beobachter in fest alternierender Reihenfolge. Cipherbytes und Tagfolgen müssen zwischen Wiederholungen, Beobachtervarianten und Grants identisch sein. Der Koordinatorlauf ist PASS, 419,529 s, Spitzen-RSS 719 MiB.

Die Zahlen sind Cipher-only-Mediane einschließlich Chunkkopien. Sie enthalten keine Produkt-KDF, ZPAQ, vollständiges Containerframing, Container-MACs, KPAR2, Originalvergleich oder Dateisystem-End-to-End-Arbeit. Der Stage-Grant 10 ersetzt keinen Auto-Pipelinevergleich. Der kanonische 25-%-Primitive-/90-%-Auto-Gate, die 24 vollständigen Produkt-KDF-Arbeitsläufe, der neue Native-/Universal-/AOT-Build 16, reale installierte GUI-Prüfung, Signierung, Notarisierung und Releasefreigabe sind durch dieses Paket nicht bestanden. Auch die gemeldeten ungefähr 12 MiB/s sind damit nicht reproduziert oder als behoben nachgewiesen.

Bei Grant 10 ergeben sich Mediane von Standard 660,40, Paranoia 153,66, Camellia 382,09 und Serpent 819,72 MiB/s. Vollständige Wiederholungen, Streuung, Beobachtervergleich, Stufen-/Schedulingdaten, Payload-/Output-/Taghashes und acht Nativehashes stehen im ungekürzten JSON. CPU-Zeit und Walltime bleiben getrennt; überlappende Stufen-/Callbackintervalle dürfen nicht addiert werden. Workerinterne Key-Expansion ist in den nativen Stufenintervallen enthalten und keine separat isolierte ABI-Messung.

## Dateien und Herkunft

| Datei | Inhalt und Bindung |
|---|---|
| [cipher-stage-profile.json](cipher-stage-profile.json) | Unveränderte vollständige Kopie des öffentlichen Originalartefakts, 2.303.627 Byte; SHA-256 `b8d00d9ca0fca371cd435c02a37081a2cbb6087612b3aef24ad1b42b0cd186f6`. |
| [test-results.json](test-results.json) | Unveränderter Koordinatorbeleg, PASS und tatsächliche Prozessdaten; SHA-256 `24778e7ce0b5bb6b63e7bf02cfb0bc93070704070bd3613b22880db36c348245`. |
| [test-timings.json](test-timings.json) | Unveränderte Zeitdatei des tatsächlichen Laufs. |
| [binary-inputs-before.json](binary-inputs-before.json), [binary-inputs-after.json](binary-inputs-after.json) | Unveränderte vollständige, identische Inventare der Harness-/Runtime-/Nativeinputs. Beide SHA-256 `dff7eaf0373d17c02dbb92e4682083bef94bac3d3661e06d2cafe2d96f4f9db8`. |
| [execution.public.json](execution.public.json) | Abgeleiteter öffentlicher Ausführungsreceipt mit UTC-Zeiten, Testargumenten, Exitcode, Quell-/Binarybindung und Originalreceipt-/Log-/Hostdateihashes. Absolute lokale CLI-Pfade und die Batteriegeräte-ID sind ausgelassen. Dies ist ausdrücklich keine unveränderte Kopie des Originalreceipts. |
| [SHA256SUMS](SHA256SUMS) | SHA-256 aller übrigen Dateien dieses Pakets. |

Das interne Originalprofil ist `work/v13-evidence/rev12-cipher-stage-profile-20261003T103749297-6cdc70b66f2f40698b8643cdf5069064.json`. Die übrigen Originaldateien liegen in `work/v13-evidence/rev12-development-20261003/build-20261003T102259Z/frozen-stage-20261003T103049Z-c7dfcc2c`. Originalreceipt-SHA-256 ist `aa4074b197c32b75d6e1c01f720e4b7406a7e73f38a45aaa1b2066069f33f475`; vollständiges Quellinventar-SHA-256 ist `b99c06e1f229238fd051388f97bc6f1622c1fcf164accf81a748b9a4e4baa5fb`. Die exakten öffentlichen Kopien wurden gegen ihre Originalbytes verglichen. Es werden keine privaten Schlüsseldateien, Secretstores oder Benutzergeheimnisse mitgeliefert.

Bei der Messung wurde AC Power aufgezeichnet, Batterie vor/nach 54/60 %, ohne aufgezeichnete Thermal- oder Performancewarnung. Das bestätigt ausschließlich diese erfassten Hostbeobachtungen; es ist keine Zusage konstanter Taktung oder exklusiver CPU-Nutzung.

Die [gesamte Abnahmematrix](../../KEEP_VAULT_5_0_3_REV12_GATE_STATUS.md) führt bestandene Teilnachweise, tatsächliche FAIL-Läufe und offene finale Gates getrennt auf. Frühere fehlgeschlagene Kandidaten- oder Performanceversuche werden durch dieses bestandene Stageprofil nicht umetikettiert.
