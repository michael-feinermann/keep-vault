# Tatsächliche 24 L3-Kontrollen

Alle 24 bestehenden IDs besitzen eigene tatsächliche PASS-Belege im frischen Build070335. Kompressionsstufe 3, produktive KDF, Auto/Manual1/Manual4, KPAR2-Erstellung und gesunde Verifikation, echter Originalvergleich sowie unabhängiger Struktur-/Hashvergleich und Cleanup sind gebunden. Dies ist keine installierte AOT-/GUI-/Signierungs- oder Releasefreigabe.

Je Fall genau ein Workflow, kein Warmup und kein Median. Neue unabhängig generierte Faktoren können die KDF-Arbeit verändern. Unterschiede zwischen CPU-Präferenzen sind deshalb kein kontrollierter kausaler CPU-Skalierungsbeweis.

| Suite | Quelle, MiB | CPU | Gesamt, s | Quelle MiB/s | Archiv+Encrypt, s | Quelle MiB/s | Decrypt+Extract, s | Quelle MiB/s | KPAR2 Create, s | Healthy Verify, s | Peak RSS, MiB |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| StandardCascade | 0.00390625 | Auto | 14.375517 | 0.000272 | 4.367785 | 0.000894 | 2.763721 | 0.001413 | 4.809419 | 2.400131 | 1966 |
| StandardCascade | 0.00390625 | 1 | 27.887331 | 0.000140 | 6.322450 | 0.000618 | 5.685295 | 0.000687 | 10.428717 | 5.413084 | 1569 |
| StandardCascade | 0.00390625 | 4 | 20.664424 | 0.000189 | 4.953545 | 0.000789 | 4.312705 | 0.000906 | 7.600579 | 3.761550 | 2014 |
| StandardCascade | 256 | Auto | 75.504863 | 3.390510 | 33.368995 | 7.671792 | 31.858359 | 8.035568 | 6.665570 | 3.209504 | 1883 |
| StandardCascade | 256 | 1 | 87.905281 | 2.912225 | 36.577167 | 6.998902 | 33.657061 | 7.606131 | 11.961049 | 5.309193 | 1639 |
| StandardCascade | 256 | 4 | 86.041108 | 2.975322 | 35.543550 | 7.202432 | 34.922477 | 7.330522 | 10.357916 | 4.774952 | 2393 |
| ParanoiaCascade | 0.00390625 | Auto | 17.620454 | 0.000222 | 5.396830 | 0.000724 | 3.328514 | 0.001174 | 5.930639 | 2.927469 | 1255 |
| ParanoiaCascade | 0.00390625 | 1 | 58.006540 | 0.000067 | 13.020255 | 0.000300 | 11.363285 | 0.000344 | 22.541666 | 11.045279 | 1817 |
| ParanoiaCascade | 0.00390625 | 4 | 27.231083 | 0.000143 | 6.851297 | 0.000570 | 5.381726 | 0.000726 | 9.993910 | 4.968397 | 1599 |
| ParanoiaCascade | 256 | Auto | 86.308179 | 2.966115 | 37.761357 | 6.779417 | 34.809691 | 7.354274 | 8.893238 | 4.425579 | 1692 |
| ParanoiaCascade | 256 | 1 | 137.450085 | 1.862494 | 49.200884 | 5.203159 | 44.173900 | 5.795277 | 29.216604 | 14.457852 | 1935 |
| ParanoiaCascade | 256 | 4 | 91.128130 | 2.809231 | 37.867331 | 6.760445 | 29.595482 | 8.649969 | 16.194889 | 7.045209 | 2159 |
| Camellia256 | 0.00390625 | Auto | 10.750681 | 0.000363 | 2.835664 | 0.001378 | 2.126143 | 0.001837 | 3.941886 | 1.802441 | 1566 |
| Camellia256 | 0.00390625 | 1 | 22.494996 | 0.000174 | 5.406645 | 0.000722 | 4.752281 | 0.000822 | 8.186922 | 4.113671 | 1442 |
| Camellia256 | 0.00390625 | 4 | 17.439713 | 0.000224 | 4.049579 | 0.000965 | 3.690104 | 0.001059 | 6.596872 | 3.059070 | 1907 |
| Camellia256 | 256 | Auto | 62.224751 | 4.114119 | 26.444702 | 9.680578 | 27.471514 | 9.318744 | 5.376238 | 2.531842 | 1785 |
| Camellia256 | 256 | 1 | 74.888733 | 3.418405 | 32.596166 | 7.853684 | 27.139356 | 9.432796 | 10.326134 | 4.447526 | 1458 |
| Camellia256 | 256 | 4 | 84.317039 | 3.036160 | 34.477427 | 7.425148 | 34.705794 | 7.376290 | 9.888261 | 4.808732 | 2250 |
| Serpent256 | 0.00390625 | Auto | 12.869680 | 0.000304 | 3.714827 | 0.001052 | 2.436044 | 0.001604 | 4.536906 | 2.138403 | 1679 |
| Serpent256 | 0.00390625 | 1 | 23.700250 | 0.000165 | 5.307610 | 0.000736 | 4.884690 | 0.000800 | 8.959821 | 4.504201 | 1365 |
| Serpent256 | 0.00390625 | 4 | 19.651060 | 0.000199 | 4.783162 | 0.000817 | 3.808886 | 0.001026 | 7.231442 | 3.783038 | 1831 |
| Serpent256 | 256 | Auto | 71.805589 | 3.565182 | 33.912916 | 7.548746 | 29.782141 | 8.595755 | 5.551512 | 2.166700 | 1572 |
| Serpent256 | 256 | 1 | 94.196235 | 2.717731 | 38.693970 | 6.616018 | 30.917016 | 8.280230 | 16.406398 | 7.788084 | 2163 |
| Serpent256 | 256 | 4 | 65.731876 | 3.894610 | 28.307589 | 9.043511 | 26.657148 | 9.603428 | 6.983811 | 3.384868 | 1752 |

Die Tabelle zählt jedes Originalbyte einmal. Die 256-MiB-Fixture enthält weiterhin ungefähr 75 Prozent Wiederholungsmuster und 25 Prozent öffentliche deterministische Pseudorandomdaten; komprimierte Cipherbytes sind eine andere Bytebasis.

| Test-ID | Quellbytes | Komprimierte Payloadbytes | Containerbytes | Recoverybytes |
|---|---:|---:|---:|---:|
| performance.rev12-workflow-4kib-standard-auto | 4096 | 3047 | 5077 | 151552 |
| performance.rev12-workflow-4kib-standard-manual1 | 4096 | 3047 | 5042 | 151552 |
| performance.rev12-workflow-4kib-standard-manual4 | 4096 | 3047 | 5082 | 151552 |
| performance.rev12-workflow-256mib-standard-auto | 268435456 | 67170268 | 67172337 | 10215424 |
| performance.rev12-workflow-256mib-standard-manual1 | 268435456 | 67170268 | 67172332 | 10215424 |
| performance.rev12-workflow-256mib-standard-manual4 | 268435456 | 67170268 | 67172332 | 10215424 |
| performance.rev12-workflow-4kib-paranoia-auto | 4096 | 3047 | 5765 | 151552 |
| performance.rev12-workflow-4kib-paranoia-manual1 | 4096 | 3047 | 5780 | 151552 |
| performance.rev12-workflow-4kib-paranoia-manual4 | 4096 | 3047 | 5795 | 151552 |
| performance.rev12-workflow-256mib-paranoia-auto | 268435456 | 67170268 | 67173050 | 10215424 |
| performance.rev12-workflow-256mib-paranoia-manual1 | 268435456 | 67170268 | 67173060 | 10215424 |
| performance.rev12-workflow-256mib-paranoia-manual4 | 268435456 | 67170268 | 67173085 | 10215424 |
| performance.rev12-workflow-4kib-camellia-auto | 4096 | 3047 | 4888 | 151552 |
| performance.rev12-workflow-4kib-camellia-manual1 | 4096 | 3047 | 4913 | 151552 |
| performance.rev12-workflow-4kib-camellia-manual4 | 4096 | 3047 | 4893 | 151552 |
| performance.rev12-workflow-256mib-camellia-auto | 268435456 | 67170268 | 67172129 | 10215424 |
| performance.rev12-workflow-256mib-camellia-manual1 | 268435456 | 67170268 | 67172094 | 10215424 |
| performance.rev12-workflow-256mib-camellia-manual4 | 268435456 | 67170268 | 67172094 | 10215424 |
| performance.rev12-workflow-4kib-serpent-auto | 4096 | 3047 | 4892 | 151552 |
| performance.rev12-workflow-4kib-serpent-manual1 | 4096 | 3047 | 4892 | 151552 |
| performance.rev12-workflow-4kib-serpent-manual4 | 4096 | 3047 | 4892 | 151552 |
| performance.rev12-workflow-256mib-serpent-auto | 268435456 | 67170268 | 67172133 | 10215424 |
| performance.rev12-workflow-256mib-serpent-manual1 | 268435456 | 67170268 | 67172108 | 10215424 |
| performance.rev12-workflow-256mib-serpent-manual4 | 268435456 | 67170268 | 67172123 | 10215424 |

Die vollständigen acht additiven Außenintervalle samt Workflowprozent stehen je Fall in summary.json und im bytegleichen Originalprofil unter matrix/<Test-ID>/workflow-profile.json. Ihre Summe ist die tatsächliche monotone Gesamtwandzeit einschließlich Owner-/Fixturecleanup. Die separaten Servicezeiten können zusätzlichen Prüfaufwand ausschließen.

Innere KDF-/Cipher-/MAC-Aggregate und native Callback-/Joinzeiten sind überlappend und werden nicht zur Gesamtzeit addiert. summary.json erhält diese Aggregate, ihre tatsächlichen öffentlichen Bytebasen und die separate MAC-Aufteilung. Prozess-CPU ist keine Wandzeit; die kombinierte Beobachtung kann unsampled terminale ZPAQ-CPU auslassen und enthält Fixturecleanup-CPU nicht. Es gibt keinen behaupteten CPU-Anteil je Cipher.

Originalsnapshot, Hash, Original-/Strukturvergleich, Memoryadmission und Cleanup sind als eigene originale Service- beziehungsweise Außenintervalle erhalten. Host-Vorher-/Nachherausgaben werden unverändert pro Fall kopiert und in summary.json gebunden. Sie belegen nur Fallrandabfragen, keine kontinuierliche Netz-, Thermal- oder Nebenlastbedingung. Die tatsächlichen Energieausgaben sind zu lesen; AC wird nicht vorausgesetzt oder nachträglich behauptet.

historical-administration-not-run bewahrt den ursprünglichen abgewiesenen Verwaltungsstart: 24 NOT RUN, kein Produktchild und keine gemessenen Produktworkflows. Die neue Matrix ist eine neue erste tatsächliche Produktausführung dieser 24 IDs, kein wiederholter vorheriger Produkt-PASS. Die originale Korrekturreceipt ist unter binding erhalten.

COPY_VERIFICATION.json nennt die bytegleichen Originalpfade und Hashes. SHA256SUMS bindet sämtliche Nutzdateien und enthält sich selbst nicht. Originale wurden nicht verändert; es gab keine Testwiederholung und keine BenchmarkJSON-Änderung durch diesen Publisher. Bei einem aktuellen FAIL/NOT RUN oder nicht passenden Belegen erzeugt er keine PASS-Publikation.
