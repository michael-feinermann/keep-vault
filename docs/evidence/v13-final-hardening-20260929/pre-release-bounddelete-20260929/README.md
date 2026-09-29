# Schlüsselfreier BoundDelete-Test, 29.09.2026

PASS auf macOS arm64, Exit 0, Laufzeit einschließlich des isolierten C-Helper-Compiles 0,383 Sekunden. Das unveränderte Originalskript wurde mit zsh-Tracing ausgeführt. `test.log` enthält den tatsächlichen Aufrufpfad, `result.json` Quellhashes vor/nach dem Lauf, Compilerangabe, Hash des ausgeführten Helfers und die vier Ergebnisgruppen.

Geprüft wurden fünf reale synthetische Fälle: normales Dateilöschen; rekursives Verzeichnislöschen ohne Verfolgen eines externen Symlinks; Erkennung eines ausgetauschten Inodes mit Erhalt des fremden Objekts in der Quarantäne (Exit 68); Ablehnung einer Quarantäne mit unzulässigem Modus (Exit 66); Ablehnung einer falschen Elternverzeichnisidentität (Exit 65). Die jeweiligen geschützten Dateien und das Symlinkziel blieben erhalten. Das temporäre Testverzeichnis wurde vollständig entfernt.

Der tatsächlich ausgeführte Helfer wurde nach seinem Wechsel zu Modus 0500 über einen geöffneten Dateideskriptor erfasst. Seine Bytes blieben bis Prozessende identisch; die Belegkopie `InstallerBoundDelete.test` ist nicht ausführbar (0400). SHA-256: `9EF9399A55C46BB5E7F7E6DB7F0966FBCE4C507FB9D6FA919F19AF8547D2DD12`.

Keine Produktquellenänderung, kein Produktbuild, keine Release-Schlüssel und keine Signierung. Dieser isolierte Regressionstest belegt keine vollständige Installation, Paketfreigabe oder GUI-Prüfung.
