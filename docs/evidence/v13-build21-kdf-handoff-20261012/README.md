# Keep Vault 5.0.3, v13: KDF- und Schlüsselübergaben

Status: PRELIMINARY. Diese Nachweise betreffen die gezielten Prüfungen für den vorgeschlagenen Kandidaten v5.0.3-rc.build21. Sie erteilen keine Gesamtfreigabe und belegen keinen bereits signierten, notarisierten, installierten oder öffentlich heruntergeladenen Build 21.

Maßgeblich sind Campaign 03 vom 12.10.2026, die unveränderten Einzeldateien und die geprüften Zahlen in [collection.json](collection.json). [SHA256SUMS](SHA256SUMS) bindet jede kuratierte Datei an ihre tatsächlichen Bytes. Der Collector liest ausschließlich ausdrücklich benannte Eingaben und feste, bekannte Dateinamen. Er führt keine Tests oder Binärdateien aus und verändert keine Eingabelogs.

## Geprüfter Umfang

| Bereich | Erfasster Umfang | Bedeutung |
| --- | --- | --- |
| Managed-Kampagne | 13 KDF-/Übergabe-/Primitive-Gruppen und 4 Audit-Gruppen | Genau diese 17 Gruppen müssen einzeln PASS, Exit 0 und eine stabile Binärbindung besitzen. |
| KDF-Fehlerinjektion | 12 Suites, 626 Übergabeorte, 2.504 Fälle | Jeder Ort wird mit 00, 01, FF und fehlender Produzentenausgabe geprüft. Die KDF-Prüfung verwendet ausdrücklich das interne 8-MiB-Profil. |
| Suite- und Cipher-Verbraucher | Alle 12 Suites einschließlich fünf äußerer AEAD-Schlüsselkopien | Die normal beobachteten Orte müssen pro Kontext vollständig mit allen vier Fehlerarten geprüft sein. |
| MAC-Baum | Serielle und parallele Berechnung, zehn Orte je Kontext | Der parallele Normalfall muss mindestens zwei tatsächlich zugeteilte CPU-Permits zeigen. Die Normal-Tags werden verglichen. |
| Recovery-Zertifizierung | Sechs Orte, einschließlich beider tatsächlicher MAC-Verbraucher | Erst nach Rückkehr der wirklichen Zertifizierung darf der Test einen vollständigen Erfolg melden. |
| Geschlossene Besitzer | Drei Typen, erfolgreiche Freigabe sowie fehlgeschlagener Unlock mit Retry | Getter müssen geschlossen bleiben; eigene Array-Aliase müssen gelöscht und Lock-Zähler wiederhergestellt sein. |
| Native ABI | 161 Prüfungen in arm64 und 161 in x86_64 unter Rosetta | Tatsächliche NULL-Zeiger und gültige eigene Puffer, getrennte Prozesse pro Bibliothek; keine erfundenen Nicht-NULL-Adressen oder freigegebenen Handles. |
| Alter Fehler, neue Regression | Derselbe öffentliche Besitzertest in zwei Prozessen | Belegt ausschließlich LockedSensitiveBuffer nach einem kontrollierten Dispose-Fehler. |

Die Meldungen enthalten öffentliche Übergabe-IDs, Fehlerarten, Zähler und Aufräumergebnisse. Sie enthalten keine Schlüssel- oder Pointerwerte. Für jeden nachgeschalteten Kontext verlangt der Collector exakt einen Injektions-Treffer, kein vollständiges Ergebnis, gelöschte eigene Aliase und wiederhergestellte Lock-Zähler. Er behauptet nicht, jede private temporäre Speicherstelle unabhängig gesehen zu haben.

Die KDF-Meldung erfasst die tatsächlichen Inventare und Zahlen je Suite. Die Injektions-, Ablehnungs- und Aufräumassertionen für die 2.504 Fälle laufen im gebundenen Testcode; es gibt keine separat exportierte JSON-Zeile für jeden einzelnen KDF-Fall. Die Span-Injektion „fehlende Ausgabe“ wird nicht als echter NULL-Zeiger-Test ausgegeben. Tatsächliche NULL-Referenzen und NULL-ABI-Zeiger werden gesondert geprüft.

## Primitive und Binärbindung

Gültige Primitive-Schlüssel mit ausschließlich 00, 01 oder FF bleiben gültig. Positive Tests vergleichen sie mit unabhängigen Referenzen, soweit vorhanden. SHACAL-2 verwendet eine eigenständige verwaltete SHA-256-Rundenreferenz, die zuerst am NESSIE-Vektor geprüft wird. Bei MARS sind der CTR-/Block-Kompositionsvergleich und die separat vorhandenen Botan-KATs unterschiedlich starke Nachweise. Der Kompositionsvergleich allein ist kein unabhängiges Primitive-Orakel.

Falsche Erfolgsausgaben abgeleiteter Schlüssel werden an tatsächlichen Produktionsgrenzen abgewiesen. Dies ist kein allgemeines Verbot konstanter Primitive-Schlüssel.

Die Kampagne bindet Harness, Product-Assembly, SDK-Host und Native-Testdateien mit SHA-256. Der Collector prüft diese ausdrücklich referenzierten Dateien erneut. Er verlangt dieselbe Product-Assembly im neuen Regressionstest, prüft individuelle Vorher-/Nachher-Receipts und den unveränderten öffentlichen Probe-Quelltext. Ein gemeldeter Git-HEAD bei verändertem Arbeitsbaum wird als solcher belassen; dies ersetzt keine vollständige eingefrorene Build-Provenienz.

Neun native Bibliotheken gehören zum geprüften Produktpfad. Beide ABI-Durchläufe müssen dafür exakt dieselben Bytes wie die Kampagne verwenden. Die zehnte ABI-Bibliothek libsha3_ref.dylib ist eine separat gebundene arm64- bzw. x86_64-Testreferenz und kein ausgelieferter Produktbestandteil. Auch libmldsa87_ref.dylib im Managed-Testinventar ist kein zehnter Produkt-Cipher.

## Frühere Versuche

Campaign 01 meldete 15 erfolgreiche Gruppen. Der tatsächliche Managed-NULL-Test und der spätere Audit-Close-/Join-Test fehlten. Zudem unterdrückte der Coordinator damals öffentliche Worker-Matrixmeldungen. Die fehlenden JSON-Nachweise werden nicht aus dem Gruppenstatus rekonstruiert. Campaign 03 ersetzt diesen unvollständigen Capture.

Der erste x86_64-Durchlauf gegen gestagte Bibliotheken bestand 155 Prüfungen. Die neun Produktbibliotheken bestanden; die arm64-only SHA3-Testreferenz ließ sich nicht laden. Das ist ein fehlgeschlagener Stagingversuch, kein bestandener 161-Fälle-Lauf. Erst der vollständige erneute Lauf mit separat gebundener x86_64-Testreferenz zählt. Der Fehlreceipt bleibt durch SHA-256 und geprüfte Klassifizierung erhalten. Raw-Dyld-Fehlertext mit möglichen Speicheradressen wird nicht veröffentlicht.

Der frühere fehlgeschlagene Harness-Build bleibt ebenfalls als fehlgeschlagener Versuch klassifiziert. Terminal-Receipt und Log-Hash bleiben erhalten; Roh-Buildlogs werden nicht veröffentlicht. Die tatsächlichen Klassifizierungen stehen in collection.json unter supersededAttempts.

## Grenzen und offene Freigaben

Das 8-MiB-Profil ist keine Prüfung vollständiger Produktions-KDF-Kosten und kein Performance-Lauf. Die vier Audit-Harness-Tests prüfen Parserisolation, passive Messung, Metadaten-Privatsphäre und den tatsächlichen Fenster-Dispose-/Initialisierungs-Join. Sie ersetzen keine Bedienprüfung der installierten NativeAOT-App mit realer Kamera und menschlicher Mausentropie.

Vollständige in-scope Produktions-, Performance- und reale GUI-Freigaben, neue Signierung und Notarisierung sowie öffentliche Download- und Installationsnachweise müssen zum eingefrorenen neuen Kandidaten passen. Build-20-Nachweise werden nicht auf Build 21 umetikettiert. Windows und physische Mehr-TiB-Tests bleiben getrennt außerhalb des macOS-Testumfangs. Der enge Vorher-/Nachher-Test führt weder native RAM-Locks noch eine alte vollständige KDF-Matrix aus.

## Reproduktion

[Collect-KdfHandoffEvidence.py](../../../tools/Collect-KdfHandoffEvidence.py) verlangt --campaign, --native-arm64, --native-x64, --owner-comparison und --destination. Die ausdrücklich benannten älteren Versuche können mit --superseded-native-x64, --superseded-build-terminal und --superseded-campaign ergänzt werden. Keine Option führt einen Test aus oder wählt einen Krypto-Provider.

Unbekannte Schemata, fehlende Matrixdaten, andere Test-IDs, Hash-Abweichungen oder unvollständige Aufräummeldungen führen zu UNAVAILABLE und Exit 2. Die erfolgreiche Prüfung erzeugt TARGETED_CAPTURE_VERIFIED, immer mit preliminary: true und releaseApproved: false. Frühere Ausgaben werden nicht überschrieben.
