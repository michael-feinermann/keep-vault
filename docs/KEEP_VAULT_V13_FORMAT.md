# Keep Vault 5.0.3: Containerformat v13

Stand: 28. September 2026, REV9. Diese Spezifikation beschreibt den aktuellen Implementierungsvertrag. Sie ist kein Freigabebericht. Die laufende Umsetzung und Prüfung ist auf macOS beschränkt. Die übrigen Testdaten sind auf höchstens 256 MiB begrenzt. Die ausdrücklich gewünschte Paranoia-Strukturprüfung ergänzt einen 256-MiB-Baum um eine zusätzliche Einzeldatei mit exakt 256 MiB, insgesamt 512 MiB. Es liegen damit keine neuen realen 1-TiB- oder 4-TiB-Nachweise vor.

## Generation und Framing

Keep Vault 5.0.3 schreibt und liest ausschließlich Container mit `Version=13`. Ältere und unbekannte zukünftige Versionen werden verworfen. Es gibt keinen Legacy-Reader, Konverter oder alternativen Ableitungspfad. Bestehende Benutzerarchive werden nicht verändert.

```text
KZPAQ2\0
|| LE32(HeaderBytes.Length)
|| kanonischer UTF-8-JSON-Header
|| globales HMAC-SHA3-512-Tag (64 Byte)
|| globales Skein-MAC-1024-Tag (128 Byte)
|| Chunk 0
|| Chunk 1
|| ...
```

Der Header ist auf 16 KiB begrenzt. Der Reader deserialisiert ihn in genau einen bekannten Record und vergleicht anschließend die ursprünglichen Bytes mit dessen kanonischer Serialisierung. Unbekannte, doppelte, fehlende oder anders dargestellte Felder können deshalb nicht stillschweigend ignoriert werden. Algorithmus, Breiten, KDF-Kennungen, Salze, Nonces und Threefish-Tweak werden vor der teuren Ableitung geprüft. Alle Base64-Felder müssen exakt ihrer gepaddeten Standard-Base64-Rückcodierung entsprechen; Leerraum und nichtnullige unbenutzte Paddingbits sind ungültig. Ohne Threefish-Tweak steht `Tweak=null`, nicht eine leere Zeichenfolge. Vor der globalen MAC-Prüfung sind Headerinformationen nicht authentifiziert.

Ein Chunk enthält höchstens `16 * 1024 * 1024 = 16.777.216` Payloadbytes. Bei AEAD-Suites folgt genau ein vollständiges 16-Byte-Tag. Der letzte Chunk darf kürzer sein; ein vollständiger Container ohne Payload ist ungültig. Chunkindizes und Streamlängen sind nichtnegative 64-Bit-Werte. Geordnete Ausgaben, Additionen, Indexschritte und relevante Offsetprodukte werden auf Überlauf geprüft.

## Suitekatalog

Die ID bleibt unabhängig von der GUI-Position. Die Reihenfolge der folgenden Tabelle ist die GUI-Reihenfolge. Schlüsselbreiten bezeichnen Speicherbreiten, keine behauptete Gesamt-Sicherheitsstärke.

| ID / Enum | Stufen außen nach innen | Cipher-Key Byte | Stage-Nonce Byte | Block Byte | AEAD | Master-Runden |
|---|---|---:|---:|---:|---|---:|
| 2 / `StandardCascade` | XChaCha, Threefish, Kalyna, AES | 256 | 232 | 128 | ja | 1 |
| 4 / `XChaChaOverAes` | XChaCha, AES | 64 | 40 | 64 | ja | 1 |
| 9 / `MixedCascade` | XChaCha, Threefish, AES | 192 | 168 | 128 | ja | 1 |
| 3 / `ParanoiaCascade` | XChaCha, Threefish, Kalyna, SHACAL-2, Serpent, Camellia, MARS, AES | 440 | 312 | 128 | ja | 2 |
| 1 / `Threefish1024` | Threefish-1024-CTR | 128 | 128 | 128 | nein | 1 |
| 0 / `Kalyna512_512` | Kalyna-512/512-CTR | 64 | 64 | 64 | nein | 1 |
| 7 / `Shacal2_512` | SHACAL-2-512-CTR | 64 | 32 | 32 | nein | 1 |
| 6 / `Mars448` | MARS-448-CTR | 56 | 16 | 16 | nein | 1 |
| 5 / `Aes256` | AES-256-CTR | 32 | 16 | 16 | nein | 1 |
| 10 / `Camellia256` | Camellia-256-CTR | 32 | 16 | 16 | nein | 1 |
| 11 / `Serpent256` | Serpent-256-CTR | 32 | 16 | 16 | nein | 1 |
| 8 / `XChaCha20Poly1305` | XChaCha20-Poly1305 | 32 | 24 | 64 | ja | 1 |

XChaCha bezeichnet immer XChaCha20-Poly1305. Jede Suite verwendet zusätzlich beide globalen MACs mit getrennten 64- und 128-Byte-Schlüsseln. Threefish-Suites haben zusätzlich einen 16-Byte-Tweak. `CascadeCipher.XChaCha20Poly1305` behält Wert 5; Camellia und Serpent ergänzen die internen Werte 6 und 7. Die öffentlichen Suite-IDs 0 bis 9 bleiben unverändert.

`ArchiveNonceBytes=320` gilt für alle zwölf Suiten. Es bezeichnet die fünf gespeicherten 64-Byte-Blöcke von B1. Nur Paranoia speichert zusätzlich B2 mit nochmals 320 Byte. `StageNonceBytes` bezeichnet dagegen die oben aufgeführte Summe der tatsächlich benötigten Stufen-IVs. Die GUI-Reihenfolge ändert keine numerischen IDs.

`Default = EncryptionSuite.StandardCascade`. Öffentliche und interne Erzeugungsüberladungen ohne Suite verwenden diesen Wert. Explizite Einzel-Kalyna-Aufrufe bleiben Einzel-Kalyna. Gespeicherte gültige GUI-Präferenzen bleiben erhalten; historische Textnamen werden ausschließlich im Präferenzparser auf die entsprechenden numerischen IDs abgebildet. Diese Texte sind keine Enum-Aliase und keine akzeptierten Archivkennungen.

Der neue Standardalgorithmus lautet exakt:

```text
XChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(AES-256-CTR)))+HMAC-SHA3-512+Skein-MAC-1024
```

Die übrigen AEAD-Kennungen entsprechen `EncryptionSuiteCatalog`: der äußere Name ist stets `XChaCha20-Poly1305`; alte ChaCha20-Poly1305-Kennungen werden nicht akzeptiert.

## Standardlayout

Alle Intervalle sind halboffen. Die Noncebereiche beziehen sich auf den abgeleiteten Chunk-Nonce, nicht auf einen direkt verwendeten Ausschnitt der Archivbasis.

| Index | Cipher | Keybereich | Noncebereich | Block |
|---:|---|---|---|---:|
| 0 | AES-256-CTR | `[0,32)` | `[0,16)` | 16 |
| 1 | Kalyna-512/512-CTR | `[32,96)` | `[16,80)` | 64 |
| 2 | Threefish-1024-CTR | `[96,224)` | `[80,208)` | 128 |
| 3 | XChaCha20-Poly1305 | `[224,256)` | `[208,232)` | 64 |

Der Header enthält `EncryptionKeyBits=2048`, `NonceBits=2560`, `BlockBits=1024`, `TweakBits=128`, `MasterKeyBits=1024`. `DerivedKeyBytes=448` ist die Summe der vier Cipher-Schlüssel und beiden globalen MAC-Schlüssel. Es ist keine Argon2-Ausgabelänge. Standard besitzt keine zweite Runde und keinen zweiten Archiv-Nonce.

Paranoia besitzt acht Stufen in dieser inneren Reihenfolge: AES, MARS, Camellia, Serpent, SHACAL-2, Kalyna, Threefish, XChaCha. Die Schlüsselbreiten sind 32, 56, 32, 32, 64, 64, 128, 32 Byte; die Stufen-Noncebreiten 16, 16, 16, 16, 32, 64, 128, 24 Byte. Damit sind `EncryptionKeyBytes=440`, `StageNonceBytes=312`, `DerivedKeyBytes=632` und `ThreefishStageIndex=6`. Der Algorithmusstring ist exakt:

```text
XChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(SHACAL-2-512-CTR(Serpent-256-CTR(Camellia-256-CTR(MARS-448-CTR(AES-256-CTR)))))))+HMAC-SHA3-512+Skein-MAC-1024
```

Der kanonische Header fügt unmittelbar nach `Nonce` das Pflichtfeld `NonceDerivationMode="Seed320-Blockwise64-SHA3-512-ActivePrefix-v3"` ein. B1 hat immer `NonceBits=2560`. Paranoia hat `SecondNonceBits=2560` und B2 mit 320 Byte. Andere Suiten haben `SecondNonceBits=0` und `SecondNonce=null`. Fehlende, alte oder unbekannte Modi sowie verkürzte Basen sind ungültig.

## XChaCha und Chunkbindung

Der produktive AEAD-Adapter verlangt 32 Byte Schlüssel, 24 Byte externen Nonce, 16 Byte Tag und höchstens 16 MiB Payload. HChaCha20 und ChaCha20 verwenden jeweils 20 Runden.

```text
K_sub = HChaCha20(K, N[0:16])
N_inner = 0x00000000 || N[16:24]
(C,T) = ChaCha20-Poly1305(K_sub, N_inner, Payload, AAD)
```

HChaCha20 hat kein Feed-forward. Seine Ausgabewörter sind 0,1,2,3,12,13,14,15 in Little-Endian-Reihenfolge. Der innere ChaCha-Block 0 erzeugt den Poly1305-Schlüssel, die Payload beginnt bei Block 1. Ein voller Chunk benötigt 262.144 ChaCha-Blöcke. Der interne Blockcounter wird niemals mit dem 64-Bit-Archivindex verwechselt.

Die blockweise ActivePrefix-v3-Ableitung ist exakt:

```text
D = UTF8("Kalyna-ZPAQ/v13/chunk-nonce/Blockwise64-ActivePrefix-SHA3-512-v3")
B = B1 || gegebenenfalls B2           # 320 oder 640 Byte
m = len(B) / 64                      # 5 oder 10
W = StageNonceBytes
k = ceil(W / 64)                     # erforderlich: 1 <= k <= m
R_j = SHA3-512(
 LP_LE32(D) || LE32(13) || LE32(SuiteID) || LP_LE32(UTF8(Algorithm))
 || LE32(m) || LE32(k) || LE32(W)
 || BE64(ChunkIndex) || BE32(j) || B[64*j:64*j+64]
)                                   # ausschließlich 0 <= j < k
Active = R_0 || ... || R_(k-1)
StageNonce = Active[0:W]
```

Es gibt keinen zweiten Stufenhash und keinen Hashauftrag für Reserveblöcke. Ein unveränderlicher, kataloggebundener `ChunkNoncePlan` wird pro Operation erstellt. Standard rotiert vier von fünf Blöcken: 256 aktive Ausgabebytes liefern 232 Stufenbytes. Paranoia rotiert fünf von zehn Blöcken: 320 aktive Ausgabebytes liefern 312 Stufenbytes. Dabei bleibt B2 vollständig Reserve. Ein zukünftiger, ausdrücklich registrierter 321-Byte-Stufenplan würde erstmals den sechsten Block aus B2 benötigen; mehr als 640 Byte sind mit zwei Basen ungültig. Die aktuelle Registrierung enthält keinen solchen Zukunftsplan.

Reservebytes beeinflussen die rohen Stage-Nonces nicht. Sie bleiben durch vollständigen Header, AAD und bei B1 auch den Threefish-Tweak gebunden. SHA3 ist keine bewiesene Bijektion; weder die gespeicherte Breite noch beobachtete Verschiedenheit endlicher Testwerte beweisen Kollisionsfreiheit. `SplitAeadMaterial` entnimmt genau die letzte 32-Byte-Schlüssel- und 24-Byte-Nonce-Stufe.

Die AAD ist unverändert 36 Byte:

```text
BE32(13) || BE32(Suite-ID)
|| SHA3-512(vollständige ChunkNonceBase)[0:16]
|| BE64(ChunkIndex) || BE32(ChunkPayloadLength)
```

Der AAD-Identitätsdigest wird einmal pro unveränderlicher Operation über sämtliche 320 beziehungsweise 640 Byte berechnet. Pro Chunk werden anschließend nur Index und Nutzlänge ergänzt.

Beim Lesen müssen zuerst beide globalen MACs erfolgreich sein. Danach wird das lokale XChaCha-Tag im privaten Chunkpuffer geprüft, anschließend werden die inneren CTR-Schichten entfernt. Erst dann darf der Chunk den begrenzten ZPAQ-Eingang erreichen. Die inneren CTR-Stufen XORen unabhängige Keystreams und können beim Entschlüsseln dieselbe Reihenfolge verwenden; diese Aussage gilt nicht für die AEAD-Verifikation.

## Master, Rollen und Tweak

Vier Zugangsdaten bleiben wirksam: Benutzerpasswort, PIN und zwei generierte 1024-Bit-Faktoren. Neue Archive behalten die bisherigen Auswahlregeln. Entschlüsselung prüft die zulässige Kodierung, ohne nachträglich eine neue Auswahlpolicy auf bestehende v13-Archive anzuwenden.

Pro Master-Runde:

1. SHA3 teilt beide Faktoren in jeweils zwei 64-Byte-Hälften. Q_S ist die Verkettung der zwei SHA3-512-Ausgaben über Domain, Passwort, PIN und A1/B1 beziehungsweise A2/B2 mit LE32-Längenpräfixen.
2. Q_K ist Skein-MAC-1024-1024 über längenpräfixiertes Passwort/PIN mit Schlüssel `A || B` und eigener Personalisierung.
3. PMI ist der Big-Endian-Wert der ersten zwei SHA3-512-Bytes über den vollständigen rundenbezogenen Kontext. `memoryKiB = 1.048.576 + 16 * PMI`, also 1.048.576 bis 2.097.136 KiB.
4. Zwei sequenzielle Argon2id-v0x13-Zweige verwenden `t=4`, `p=4`, jeweils 64 Ausgabebytes, getrennte 64-Byte-Salze und runden-/zweigspezifische Associated Data. Der Master ist die byteweise Interleavung beider Ausgaben zu 128 Byte.
5. Nur Paranoia führt eine zweite vollständige Runde mit neuen Salzen aus. Der gesamte erste Master wird zum Argon2-Secret der zweiten Runde.

Headerkennungen:

```text
PasswordMode = UserPassword24to256+PIN6to16+GeneratedHex1024x2
KdfInputMode = DualBranch-v13: SplitFactorsSHA3-512-1024 || KeyedSkeinMAC-1024-1024
KdfMode = DualArgon2id-SplitSHA3+Skein1024-Sequential-Master1024
KdfMemoryMode = PMI16
KdfExecutionMode = Sequential
Argon2MemoryKiB = 0
```

Die Null im Header verhindert die Veröffentlichung des abgeleiteten PMI-Speicherwerts. Test-only-Speicherüberschreibungen sind intern, flussgebunden und nicht konfigurierbar im Produkt; Freigaben verwenden das Produktionsprofil.

Alle produktiven Master-Domänen beginnen mit `Kalyna-ZPAQ/v13/{Algorithm}/`:

```text
SHA3-512/User+PIN+Factors-A1+B1
SHA3-512/User+PIN+Factors-A2+B2
Skein-MAC-1024-1024/User+PIN/Factors-A+B-Key
SHA3-512/PMI/Round-{1|2}
Argon2id/{SHA3|Skein}-Branch/Round-{1|2}
```

Der kanonische Rollenkontext ist:

```text
LP_LE32(UTF8("Kalyna-ZPAQ/v13/RoleKey")) || LE32(13)
|| LP_LE32(UTF8(Algorithm)) || LE32(StageIndex)
|| LP_LE32(UTF8(Cipher)) || LP_LE32(UTF8(Purpose)) || LE32(KeyBits)
```

Globale Rollen verwenden StageIndex `0xFFFFFFFF`. Zwecke sind `Encryption`, `Sha3Mac`, `SkeinMac`, `RecoverySha3Certification`, `RecoverySkeinCertification`. Jeder vollständige 128-Byte-Rollenwert ist die XOR-Verknüpfung der SHA3-HKDF-Expansionen beider Masterhälften und der personalisierten Skein-MAC-Ausgabe über den ganzen Master. Erst anschließend wird auf die benötigte Schlüsselbreite gekürzt. Domains:

```text
Kalyna-ZPAQ/v13/RoleKey/HKDF-HMAC-SHA3-512
Kalyna-ZPAQ/v13/RoleKey/Skein-MAC-1024-1024
```

Der Threefish-Tweak lautet:

```text
SHA3-512(
 LP_LE32(UTF8("Kalyna-ZPAQ/v13/Threefish-1024/CTR-Tweak"))
 || LP_LE32(UTF8(Algorithm)) || LE32(ThreefishStageIndex)
 || LP_LE32(vollständiger erster Archiv-Nonce)
)[0:16]
```

Die Headerkennung ist exakt `SHA3-512(LP(Domain)||LP(Algorithm)||LE32(StageIndex)||LP(Nonce))[0..15]`. Standard verwendet Index 2, Paranoia Index 6. Jede Threefish-Suite verarbeitet genau die vollständigen 320 Byte von B1. Der Tweak wird einmal pro Operation abgeleitet; B2 gehört nicht zu dieser Tweak-Nachricht.

## Globale MACs und verifizierter Eingang

`ParallelContainerAuthenticator` behandelt `Magic || Headerlänge || Headerbytes || Ciphertext einschließlich lokaler Tags` als logischen Strom mit 1-MiB-Blättern. Jeder Blattkontext bindet BE64-Index und BE32-Länge. Der Root bindet BE64-Gesamtlänge, BE64-Blattzahl, BE32-Blattgröße und in Reihenfolge beide vollständigen Blatttags einschließlich ihrer Index-/Längenfelder. Folgende Domains sind verbindlich:

```text
Kalyna-ZPAQ/v13/Parallel-Tree-MAC/Leaf
Kalyna-ZPAQ/v13/Parallel-Tree-MAC/Root
Kalyna-ZPAQ/v13/Parallel-Tree-MAC/HMAC-SHA3-512/Leaf-Key
Kalyna-ZPAQ/v13/Parallel-Tree-MAC/HMAC-SHA3-512/Root-Key
Kalyna-ZPAQ/v13/Parallel-Tree-MAC/Skein-MAC-1024-1024/Key-Derivation
```

Die Skein-Schlüsselableitung verwendet zusätzlich `Leaf-Key` und `Root-Key` als Nachrichten. Beide Rootprüfungen werden mit UND verlangt. Trunkierung, zusätzliche Bytes, entfernte oder vertauschte vollständige Chunks und manipulierte Header verändern die Gesamtprüfung.

Der verschlüsselte Eingangsweg verwendet `VerifiedArchiveInput` als gebundenen Originalreader. Ein begrenztes Header-/Tagabbild wird vor der unveränderten KDF gehalten. Der erste vollständige Quellenpass bestätigt dieses Abbild, erzeugt die lokalen Nachweise und speist beide globalen MACs aus denselben exklusiven privaten Pufferbytes. Ein Zustand vor erfolgreicher globaler Doppelprüfung lässt keine normale Konsumenten-Leseoperation zu. Lokale Bereichstags ersetzen niemals die kryptografische Containerprüfung. Für beschädigte Quellen besteht eine getrennte lokale `RepairCiphertextRead`-Befugnis; ein Reparaturkandidat benötigt eine neue vollständige globale Verifizierung.

Jeder physische 1-MiB-Bereich ist mit unabhängigen frischen lokalen HMAC-/Skein-Schlüsseln, Operations-ID, BE64-Index und BE32-Länge gebunden. Der unveränderte Record ist 204 Byte groß. `AuthenticatedRangeIndex` hält diese Records zunächst in tatsächlich benötigten RAM-Segmenten innerhalb eines gemeinsamen 16-MiB-Ziels; größere Bestände werden unverändert in eine private authentifizierte Indexdatei migriert. Kleine Aufträge benötigen kein Arbeitsvolume. Im zweiten Quellenpass prüft der Reader den vollständigen Bereich in einem gesperrten privaten Puffer, bevor er dessen Slice freigibt. Ausschließlich eigene unveränderliche verifizierte Pufferleases dürfen Cachetreffer bedienen. Es entsteht keine vollständige Ciphertext-, Klartext- oder SHM-/VM-Kopie des Eingabearchivs.

CPU-, RAM-, I/O- und Queue-Präferenzen bleiben echte Auto-/Manualwerte. Aktive Kapazität wird aus konkretem Bedarf und aktuellen OS-Beobachtungen aufgelöst. Ein Rechenlimit von eins ist zulässig; kontrollierende Pipe-/I/O-Arbeit hält dabei keine wartenden Rechenpermits. Argon2 bleibt mit vier kryptographischen Lanes unverändert. Die KDF endet, bevor schwere native Kompressionsmodelle zugelassen werden. Der Entpack-Child erhält seine Readiness erst nach beiden globalen MACs.

Die vertrauenswürdige `ArchiveOperationPolicy` steuert Größenobergrenzen, ausdrücklich gewählte Volumes und Ressourcen. Sie stammt nicht aus dem Archiv. Erlaubtes Maximum ist keine Speicher- oder Plattenreservierung. Tatsächliche Allokationen und gleichzeitig ausstehende Writes werden separat gebucht. Normale Archivoperationen haben keine Wandzeit-, CPU-Zeit- oder Stillstandsdeadline; Fortschritt und ETA besitzen keine Abbruchbefugnis. Nutzerabbruch, Shutdown und reale Sicherheits-/Ressourcenfehler bleiben wirksam.

Reguläre `.zpaq`-Eingaben verwenden denselben lokalen Bereichsschutz über dem gebundenen Original, aber den getrennten Status `PlainIntegrityVerified`. Erst nach beiden ungeschlüsselten Hashprüfungen erlaubt `KV13RA` dem nativen Parser begrenzte Leseanfragen mit geprüften 64-Bit-Offsets und höchstens 1 MiB Länge. Die Antwort enthält ausschließlich geprüfte private Byteausschnitte; der Parser erhält keinen Archiv-FD und keine gesamte Payloadkopie. Die ungeschlüsselten globalen Hashdateien schützen weiterhin nicht vor einem Angreifer, der Original und Hashdateien gemeinsam ersetzt. Parser-, Mengen- und Metadatenbudgets bleiben verbindlich. Die Entwicklungsnachweise stehen im [REV11-Readerbericht](KEEP_VAULT_5_0_3_ORIGINAL_INPUT_REVIEW.md); kleine reale Tests belegen keine beliebigen Mehr-TB-Größen.

KPAR2-Arbeitsmetadaten verwenden `RecoveryRecordTable<T>`: feste Datensätze mit flüchtiger 32-Byte-Auftragskennung, 64-Bit-Index, Typ, Nutzlänge und beiden lokal getrennten MACs. Digest- und Paritätsdatensätze enthalten keine Archivklartexte; Metadatenströme verwenden maximal 64 KiB Nutzdaten pro Datensatz. `RecoveryMetadataBudget` begrenzt die Summe aller gleichzeitig lebenden Tabellen eines Auftrags und teilt deren RAM-first-Cache mit dem Bereichsindex. Eine Arbeitsdatei entsteht erst bei tatsächlichem Spillbedarf. Jeder Zugriff prüft den vollständigen Datensatz vor der Dekodierung. Fehler versetzen die Tabelle dauerhaft in einen gesperrten Zustand. Die neuen lokalen Domänen lauten:

```text
Kalyna-ZPAQ/v13/RecoveryRecordTable/HMAC-SHA3-512
Kalyna-ZPAQ/v13/RecoveryRecordTable/Skein-MAC-1024-1024
```

## Transport, Recovery und native Namen

Die inneren generationgebundenen Kennungen heißen `KVP13ZP1` und `KV13RA`. Das reguläre ZPAQ-Fremdformat bleibt getrennt unterstützt. KPAR2 behält seine eigene Sidecar-Formatversion 4; sein verschlüsselter Containerbezug ist 13 und verwendet dieselbe Ein-/Zweirunden-KDF sowie getrennte Recovery-Rollen.

Der produktive native AEAD-Adapter heißt `NativeXChaChaPoly`, die Bibliotheken `xchachapoly_v13.dll` und `libxchachapoly_v13.dylib`. Die versionierten XChaCha-Exporte prüfen explizite Längen. Der Kalyna-Adapter heißt `kalyna_v13` mit `keepvault_v13_kalyna_512_512_ctr_*`. Signatur- und Hashprüfung erfolgen vor dem Laden. Keine fehlende Bibliothek darf eine schwächere Suite oder alte ABI auswählen.

Release-Schlüsselumschläge `KVMDSA12` und `KVPFXP12` sind eine separate Schutzkonstruktion und bleiben unverändert. Ihr Name bezeichnet keine v12-Archivunterstützung.

## Kryptografisches Nutzungsbudget

Alle zwölf Suiten sind pro frischem Archivschlüsselsatz auf 64 TiB Payload und 2^22 Chunks begrenzt. `CryptoUsageBudget` ist unabhängig von Ressourcenfreigaben und prüft Writer, Reader, Authentifizierungs-API und MAC-Logikstrom. Das [quantitative Nutzungsprofil](KEEP_VAULT_V13_CRYPTO_USAGE.md) begründet Startkollisionen, Counterintervalle, Primitive-, AEAD- und MAC-Terme getrennt und nennt die Modellgrenzen.

## Nachweise und Grenzen

`KalynaArchiver.Tests/V13NonceTests.cs` prüft 84 unabhängige Python-Hashlib-Vektoren für alle zwölf Suiten und sieben 64-Bit-Indizes. Weitere Gruppen behandeln jeden aktiven/reservierten Block, Zukunftskapazität, Hashanzahl, Überlappung, Fehlerbereinigung und Abbruch. `KalynaArchiver.Tests/V13StandardTests.cs` wird von beiden Testinventaren kompiliert. Die stabilen IDs `v13-std-*` binden Katalog, Layout, Rollen, Tweak, 64-Bit-Nonce/AAD, Zusammensetzung, Default-APIs, Header, Framing, lokale/globale Manipulation und Formatbruch. `KeepVaultMac.Tests/Fixtures/V13Reference` enthält eigenständige Bouncy-Castle- und Python-Generatoren für v13-KDF-/MAC-/Headerwerte. Echte v12-Negativfixtures bleiben unverändert erhalten. Das Bestehen eines Tests wird ausschließlich im Laufbericht vermerkt.

CTR-Anfangswerte sind Big-Endian-Zähler, HChaCha-Wörter Little-Endian. Pro Stufe muss der gesamte verbrauchte Zählerbereich vor Ausgabe passen. Gehashte unterschiedliche CTR-Startwerte garantieren keine disjunkten vollständigen Bereiche. XChaChas größere Nonce beseitigt weder diese unabhängige Grenze der inneren Blockchiffren noch Grenzen des Dateisystems, KDF, Parsers, Ressourcenbudgets oder Benutzerendgeräts. Es gibt keine Zusage unbegrenzt sicherer Archive und keine externe Auditbestätigung.

Primärquellen: [XChaCha-Entwurf einschließlich A.3.1-Testvektor](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03), [RFC 8439 für den inneren ChaCha20-Poly1305-Aufbau](https://www.rfc-editor.org/rfc/rfc8439), [libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction), [Go NewX](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305).
