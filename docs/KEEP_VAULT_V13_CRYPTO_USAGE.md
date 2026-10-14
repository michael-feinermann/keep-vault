# v13: quantitatives Nutzungsprofil pro Archivschlüssel

Stand: 28. September 2026. Dieses Profil ergänzt REV9 ohne Änderung des Formats, des ActivePrefix-v3-Transcripts oder der KDF. Es ist eine konservative lokale Entwurfsentscheidung und keine externe Sicherheitszertifizierung. Die endlichen Zahlenprüfungen messen weder reale TiB-Verarbeitung noch Kollisionsfreiheit.

## Verbindliche Grenzen

`CryptoUsageBudget` ist von `ArchiveOperationPolicy` getrennt und nicht über GUI, Archivfelder oder Datenträgerfreigaben erhöhbar. Alle zwölf registrierten Suiten erhalten dasselbe konservative Profil. Die engste Klasse, die 128-Bit-CTR-Primitive, bestimmt diese gemeinsame Obergrenze; große Blockchiffren erhalten dadurch keine Sonderzusage.

| Geltungsbereich | Höchstwert pro neuem Archivschlüsselsatz |
|---|---:|
| Payload vor lokalen Tags | 2^46 = 70.368.744.177.664 Byte = 64 TiB |
| Chunkzahl | 2^22 = 4.194.304 |
| Payload je Chunk | 2^24 = 16.777.216 Byte |
| AES/MARS/Camellia/Serpent: Gesamtblöcke je Stufenschlüssel | 2^42 |
| SHACAL-2: Gesamtblöcke je Stufenschlüssel | 2^41 |
| Kalyna: Gesamtblöcke je Stufenschlüssel | 2^40 |
| Threefish: Gesamtblöcke je Stufenschlüssel | 2^39 |
| XChaCha: verschlüsselte Payloadblöcke insgesamt | 2^40 |
| Lokale XChaCha-Tags und zugehörige einmalige Poly1305-Schlüssel | höchstens 2^22 |
| MAC-Logikstrom einschließlich maximalem Header und lokalen Tags | 2^46 + 2^26 + 16.384 + 11 Byte |
| 1-MiB-MAC-Blätter je globaler Blattrolle | höchstens 67.108.929 |
| Root je globaler Rootrolle | ein geordneter Transcript mit allen Blatteinträgen |

Die Obergrenze gilt auch für eine letzte Teilnachricht. Ein neues Archiv benötigt neue Salts/Entropie und damit neue Rollen- und Stufenschlüssel. Das Wiederverwenden desselben Schlüsselsatzes für verschiedene Archivklartexte wäre keine erneute Freigabe von 64 TiB. Öffentliche Archivierungswege erzeugen neue Salts und verbrauchen vorbereitete Entropie einmalig. Deterministische interne Fixtures sind keine Benutzer-API zum Wiederverwenden von Archivschlüsseln. Erneutes Lesen desselben Archivs erzeugt keine neuen Verschlüsselungsanfragen.

Der Writer prüft bekannte Eingabelängen vor der KDF und unbekannte Streams vor jedem Chunkauftrag. Der Reader und reine Authentifizierungs-API prüfen die aus der physischen Ciphertextlänge bestimmte kanonische Nutz-/Tagzahl vor der KDF; die Chunkroutine prüft erneut vor Ausgabe. Der MAC-Einstieg begrenzt den logischen Strom gesondert. Ressourcengrenzen dürfen früher abbrechen. Native CTR-Routinen prüfen außerdem den gesamten lokalen Bereich vor dem ersten Output und lehnen Wrap ab.

## Risikomodell und getrennte Terme

Die folgenden Rechnungen setzen neue unabhängige Archivschlüssel, korrekte Domänentrennung, SHA3 als pseudorandom wirkende Ableitung sowie sichere Cipher-/MAC-Primitive voraus. Sie betreffen einen Archivschlüsselsatz und klassische Angreifer. Zusätzliche primitivebezogene Angreifervorteile, Implementierungsfehler, kompromittierte Endgeräte und Mehrbenutzereffekte werden nicht auf null gesetzt. Es wird keine formale Gesamtkompositionsschranke der achtfachen Kaskade behauptet.

Für q=2^22 gehashte Chunkstarts und höchstens L=2^20 Blöcke eines 128-Bit-Ciphers pro Chunk ergeben eigene Ganzzahlrechnungen:

- Gleichheit zweier Startwerte: q(q−1)/2^129 < 2^-85.
- Überlappung ganzer Intervalle: q(q−1)(2L−1)/2^129 < 2^-64. Dieser Term ist größer als bloße Startgleichheit; der lokale Wraptest ersetzt ihn nicht.
- Für die kumulierten N=2^42 Blockabfragen: N(N−1)/2^129 < 2^-45. Bei vier 128-Bit-Stufen ergibt die reine Vereinigungsabschätzung < 2^-43. Das Nutzungsprofil zielt für diese generischen datenabhängigen Terme auf eine konservative Schranke unter 2^-40 pro Archiv, mit verbleibendem Abstand für die Intervallterme.

Der letzte Term verwendet das PRP/PRF-Switching-Lemma. Dieses vergleicht ideale Permutationen und Funktionen, beweist aber keine konkrete Cipherstärke. Der jeweilige reale PRP-Vorteil kommt separat hinzu. Die Rechnung ist eine eigene Anwendung des Lemmas aus [Bellare/Rogaway, Abschnitt 4.9, Lemma 4.17](https://web.cs.ucdavis.edu/~rogaway/classes/227/spring05/book/main.pdf). Das CTR-Verbot wiederholter Counterblöcke und die Verwendung kompletter Counterbreiten bleiben dem Modusvertrag verpflichtet; siehe [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

Für die 256-/512-/1024-Bit-Blockchiffren werden dieselben Formeln mit ihrer tatsächlichen Blockbreite und den kleineren Blockzahlen angewendet. Größere Noncebasen verändern diese Blockbreiten nicht. Es wird kein Sicherheitsgewinn aus aktuell ungenutzten Reserveblöcken angesetzt.

Für q=2^22 vollständige 192-Bit-XChaCha-Nonces ist der separate Birthday-Term q(q−1)/2^193 < 2^-149. Der innere Payloadcounter verwendet nur 1 bis 2^18; Block 0 erzeugt den Poly1305-Schlüssel. HChaCha-/ChaCha-PRF-Annahmen bleiben zusätzlich erforderlich. Die innere Konstruktion und ihr Countervertrag folgen [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439); die Erweiterung folgt dem [XChaCha-Entwurf](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03).

Als gesondertes Integritätsmodell werden höchstens v=2^32 gezielte Fälschungsversuche je Schlüssel angenommen. Bei 36 Byte AAD und höchstens 16 MiB Ciphertext ist L=2^20+3 in 16-Byte-Einheiten. Die tatsächlich authentifizierte Poly1305-Nachricht besitzt zusätzlich den abschließenden 16-Byte-Block mit beiden LE64-Längen, also genau L+1=2^20+4 Blöcke. Dieser Block ist im folgenden L+1-Term ausdrücklich enthalten. Der innere Poly1305-Term v(L+1)/2^103 liegt unter 2^-50. Diese Rechnung verwendet die Formel für den inneren ChaCha20-Poly1305-Aufbau aus [CFRG AEAD-Limits, Fassung 08, Abschnitt 5.2.2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits-08#section-5.2.2); sie übernimmt nicht dessen 96-Bit-Nonceannahme für die gesamte XChaCha-Konstruktion. Nonce- und HChaCha-Terme bleiben getrennt.

Ein lokaler Reader kann globale Offlineversuche oder kopierte Programme nicht zählen. v ist deshalb eine offen benannte Modellannahme, keine behauptete weltweit durchgesetzte Sperre. Innerhalb eines Aufrufs brechen ungültige globale Tags vor jeder Entschlüsselung ab; lokale Tagfehler brechen ebenfalls ab. Beide globalen MACs müssen gültig sein. Im idealen PRF-Modell sind direkte Tagraten für v Versuche höchstens v/2^512 beziehungsweise v/2^1024. Ohne unabhängigen Kompositionsbeweis werden diese Werte nicht multipliziert. Die realen PRF-Sicherheitsterme für HMAC-SHA3 und Skein sowie die gesamte Blatt-/Root-Datenmenge bleiben Bestandteil der Annahmen; [Skein-Spezifikation](https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf) und [NIST-Übersicht SHA-3](https://csrc.nist.gov/projects/hash-functions) sind Primitivequellen, keine Begutachtung dieses Baums.

## Prüfung und verbleibende Grenzen

`v13-usage-boundaries` prüft alle zwölf Suiten, vollständige und letzte Teilchunks, 256/500/512 GiB, 10^12 Byte, 1/2/4/8 TiB, 64 TiB ± 1 Byte, fehlerhafte Tagreste und Int64-Grenzen rein arithmetisch. `v13-usage-model` prüft die oben genannten Ungleichungen mit exakten Ganzzahlen. Diese Tests schreiben keine großen Datenmengen. Aktuelle reale Tests bleiben auf höchstens 256 MiB beschränkt, mit der ausdrücklich gewünschten Paranoia-Struktur-Ausnahme von insgesamt 512 MiB.

64 TiB ist keine Leistungszusage und kein unbegrenzt oft wiederverwendbares Kontingent. Eine Erweiterung würde neue Risikoentscheidungen oder ein separat spezifiziertes Rekeying-/Formatdesign erfordern. Die gehashte ActivePrefix-v3-Route wird dafür nicht still geändert. Das Profil sagt weder einen Gesamt-Sicherheitswert von 256/512/1024 Bit noch Schutz gegen Rollback, vollständigen Schlüsseldiebstahl oder unbekannte primitivebezogene Schwächen zu.
