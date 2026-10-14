# REV12: DragOver und Acquire-Reentry, begrenzte Quellkorrektur

Status: SOURCE REVIEW PASS am gebundenen Drei-Dateien-Stand. Der unabhängige Peer rev12_dispose_resume hat diesen Stand gelesen und keine weitere konkrete Finding gemeldet. Laufzeitnachweise der neuen Bytes kommen aus dem von Root gestarteten frischen fokussierten Lauf. Dieser Reviewer hat keinen Build, Test oder Produktlauf ausgeführt.

## Befunde und Korrektur

1. Die neun tatsächlichen DragOver-Ereignisse konnten Provider-Path-Ausnahmen zur UI durchlassen; ExtractPanel las Path zusätzlich vor seiner gemeinsamen Grenze. Die synchronen Ereignisse setzen jetzt None/Handled vor Transfer/Path/Routing, verweigern bei Fehler und schreiben ausschließlich in den vorhandenen begrenzten Konsolenlog. Hover übernimmt und entsorgt keine Provideritems. Die tatsächliche Drop-Fehlergrenze mit Dialog bleibt erhalten.
2. Ein Path-Callback während nativer Acquire konnte vor der ersten Ownerbindung denselben Provider erneut an Retain übergeben. Dadurch konnten zwei Leases für dieselbe Raw-Referenz entstehen und eine die Referenz unter der anderen entsorgen. Ein referenzgleicher Inflightmarker umfasst jetzt genau den nativen Acquire-Aufruf mit finally-Entfernung. TryAcquire verweigert Same-Ref-Reentry, Has/Owns erkennen die Übergabe, Rawcleanup schützt den Inflightowner. Nach Close wird die gerade erworbene Lease weiterhin verworfen und unabhängig bereinigt.

## Regressionen im bestehenden Inventar

- gui.rev12-drop-storage-ownership: alle neun echten DragOver-Handler, je drei Pathfault-Wiederholungen, None/Handled, Fehlerlog, keine Dialoge/Dispose, Entropie-/Credential-/Fingerprint-/Pfad-/Tab-/Ownererhalt; normale Copy-Routen; ExtractPanel für Ordner und Archiv sowie OutputFolder mit tatsächlichem Hover und nachfolgendem Drop. Die vorhandenen unabhängigen Drop-/Cleanup-/Alias-/Retry-Beweise bleiben bestehen.
- gui.rev12-storage-transitions: echte Datei-/Ordner-Retain-Aufrufe mit nativer BeforePath-Reentry, same-Ref-Retain-Verweigerung, Rawcleanup-Schutz und Has/Owns während Übergabe; aktiver Alias nach Markerentfernung; genau eine Plain-URL-Native-Dispose-Invo­kation und genau eine Raw-Dispose; Markerabbau nach Acquirefailure und Closecallback. Die vorhandenen Retirement-, Batch-, Picker- und Retry-Beweise bleiben bestehen.

Der native skalare Observer ist nur im Testscope aktiv. Plain-URL-Nachweise belegen tatsächliche Dispose-Aufrufe, keine native YES-Grant/Stop-Abnahme. Kopflose Tests ersetzen die reale installierte/AOT-GUI-Abnahme nicht.

## Bytebindung

- KeepVaultMac/Gui/MainWindow.PathsAndDrop.cs: `22457e8b45d4edd1bf9512cce54ebb3bf57e2e857043e9ee8684e785474a459e`
- KeepVaultMac/Gui/MainWindow.StorageAccess.cs: `62517b3d5072db57d19591102692a3502ea8b92417227b710f05436d996cf655`
- KeepVaultMac.Tests/WindowDisposeRev12Tests.cs: `9dfff557a2fe1b454a1153f0882222e9426c3a56f6f5de0b163c7eabafa6baee`

HEAD bei Aufnahme: `6bfd2e4d31c3493987083379e898a0b84338a102`. Owned git diff --check: Exit 0, leere Originalausgaben. Der Diff ist vollständig in fix-source.diff erhalten; SHA-256: `c77cae7b7609443fcaad750dae4e7b31ba25b99fce3f28df73756873a6cbefe9`. Keine kopierten historischen Evidenzdateien wurden geändert.
