# Zwölf 1-GiB-Workflows am gepinnten Build 171619

Status: PASS. 12 tatsächliche PASS von zwölf geplanten Fällen. 0 Fälle noch nicht abgeschlossen. Die unabhängige Schlussauswertung bleibt ein eigener Beleg.

Jede Suite läuft seriell mit einem vollständigen gemessenen Workflow, produktiver KDF, Kompressionsstufe 5, KPAR2-Erstellung und Prüfung des unbeschädigten Containers, Entschlüsselung und Entpackung, produktivem Originalvergleich sowie unabhängigem Struktur- und Hashvergleich. Genau 1.073.741.824 Byte Quelldaten je Fall. Kein Warmup, kein Median. Managed-Release-Entwicklungsbeleg mit Build-15-Natives; die endgültige installierte AOT-GUI-Freigabe ist separat.

Hier stehen ausschließlich stabile Originalkopien abgeschlossener erfolgreicher Fälle. Quell-, Binär-, SDK-, Native-, Root-ZPAQ- und Driverbezug wurden vor und nach jedem Fall geprüft. Energiequelle, Akku und Thermalstatus sind Randbeobachtungen des Launchers; es gibt keinen kontinuierlichen Energie-, Takt- oder Temperaturnachweis. Der ältere Standardlauf am Build 154322 bleibt ein separater Beleg.

| Suite | Gesamtzeit in s | Gesamt in MiB/s | Archivierung in s | Entpackung in s |
|---|---:|---:|---:|---:|
| StandardCascade | 1484.061 | 0.6900 | 690.033 | 754.894 |
| XChaChaOverAes | 1451.344 | 0.7056 | 685.072 | 726.741 |
| MixedCascade | 1436.124 | 0.7130 | 669.453 | 727.863 |
| ParanoiaCascade | 1461.957 | 0.7004 | 679.694 | 737.506 |
| Threefish1024 | 1439.163 | 0.7115 | 672.014 | 726.550 |
| Kalyna512_512 | 1449.198 | 0.7066 | 671.382 | 737.129 |
| Shacal2_512 | 1432.726 | 0.7147 | 669.858 | 724.327 |
| Mars448 | 1440.971 | 0.7106 | 670.244 | 731.372 |
| Aes256 | 1626.111 | 0.6297 | 727.577 | 858.216 |
| Camellia256 | 1539.579 | 0.6651 | 700.238 | 801.025 |
| Serpent256 | 1582.393 | 0.6471 | 771.937 | 770.406 |
| XChaCha20Poly1305 | 1649.761 | 0.6207 | 740.047 | 867.645 |

Die strikte unabhängige [Schlussauswertung](final-evaluation-v3a/report.de.md) und ihr [Original-JSON](final-evaluation-v3a/evaluation.json) sind PASS für alle zwölf ursprünglichen Stufe-5-Fälle. Acht äußere Zeitintervalle teilen die volle Workflowzeit; innere KDF-/Cipher-/MACintervalle können überlappen. Eine Messung je Suite, kein Median; keine finale installierte AOT-/GUI-Freigabe.
