# Getrennte tatsächliche Control10k-Architekturbelege

Status: PASS.

| Architektur | Belegstatus | Tatsächliche Fälle | Harnesszeit, s |
|---|---|---:|---:|
| arm64 | VALIDATED ACTUAL PASS | 10000 | 1.7584800420008833 |
| x86_64 | VALIDATED ACTUAL PASS | 10000 | 2.317280750008649 |

ARM64 wird ausschließlich aus seinem unveränderten ursprünglichen PASS gelesen. Intel/Rosetta benötigt seinen eigenen vollständigen tatsächlichen PASS. Ein fehlender oder gescheiterter Intel-Beleg wird nicht durch ARM64 ersetzt.

Gleicher öffentlicher 10.000-Fälle-Corpus und vollständiger Verdict sind obligatorisch. Tatsächliche Wirehashes dürfen wegen zweier Caller und Reject-Rennen abweichen; jeder Lauf muss seinen bytegenauen Wireoracle erfüllt haben.

Die native Parentauthentisierung stammt aus dem unveränderten produktiven control_channel-Konstruktor. Beim Intel-Lauf sind tatsächliche Parent-/Child-PIDs, arch-Aufruf und dünnes x86_64-Mach-O separat erhalten. Originale ARM64-Reports haben kein eigenes Childexit-/PID-/UTC-Feld; diese Werte werden nicht ergänzt.

Das ist eine enge Controlframing-Semantikprüfung. Rosetta ist kein Lauf auf nativer Intel-Hardware, keine Geschwindigkeitsmessung der Anwendung und keine Intel- oder Gesamtproduktfreigabe. Eingaben sind konkret gebunden, aber nicht sämtliche Linker-/System-/Rosetta-Runtimeinputs hermetisch inventarisiert.
