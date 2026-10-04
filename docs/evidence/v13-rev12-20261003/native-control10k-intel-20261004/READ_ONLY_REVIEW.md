# Unabhängige Leseprüfung des Intel-Control10k-Pakets

Ergebnis: Paketprüfung PASS im engen Publikationsscope. Reviewer: `/root/rev12_console_resume`. Es wurde kein Runner oder Reporter importiert, kein Build oder Test ausgeführt, keine aktuelle SDK-/Binaryinventur durchgeführt und keine Datei durch den Reviewer geändert.

Die Prüfung erfolgte zunächst am vollständigen Paketmanifest SHA-256 `38b12dcc87fe4467a4f13cf35b6581083d8fc295aa01d76327b9bbfc6734f34f`. Alle 16 darin gebundenen Nutzdateihashes stimmten. Das ursprüngliche `comparison/SHA256SUMS.txt` bestätigte ebenfalls seine beiden unveränderten Nachbardateien. Die später ergänzte Reviewdatei und die aktualisierte Publikationsreceipt werden zusätzlich im abschließenden Paketmanifest erfasst. Die 14 ursprünglichen Evidence-/Quellkopien werden dabei nicht verändert.

Der Peer bestätigte die Hash- und Größenpins der 14 Originalkopien gegen die Paketbytes. Die tatsächlichen bytegleichen Kopien gegen ihre Originalpfade wurden vom Paketautor beim Zusammenstellen geprüft und in `COPY_VERIFICATION.json` dokumentiert. Es wird kein zusätzlicher aktueller Peerwalk über alle 866 SDK-/Toolchaininputs behauptet.

Der tatsächliche Intelreport SHA-256 `cc3c52dbc7376ff4ef017b202f1db8c6648657fedd31ad34fc4d6c6b5d822422` passt zur ursprünglichen Comparisonreceipt, zum README, zum vollständigen Corpus/Verdict sowie zu den C++-, Header-, Runner- und Reporterpins. Die 866 gespeicherten Vorher-/Nachher-Inputzeilen und die gespeicherte Binaryidentität sind jeweils exakt gleich. Der Originalreport erhält den tatsächlichen dünnen x86_64-Mach-O-Beleg, den arch-Aufruf, Parent-/Child-PIDs, Childexit 0 und alle 10.000 Fälle.

Der README trennt x86_64 unter Rosetta auf dem M5 von nativer Intel-Hardware, separaten historischen ARM-Sanitizerbelegen und finaler AOT-/GUI-/Releasefreigabe. Er benennt das fehlende rohe Markertranscript, das nicht mitveröffentlichte Testbinary sowie die konkreten Provenienz- und Testgrenzen. Der Peer fand keine neue konkrete notwendige Korrektur.

Diese Leseprüfung bestätigt die konsistente Veröffentlichung bereits vorhandener enger tatsächlicher Controlframing-Belege. Sie ist kein neuer Produktlauf und keine Gesamtfreigabe.
