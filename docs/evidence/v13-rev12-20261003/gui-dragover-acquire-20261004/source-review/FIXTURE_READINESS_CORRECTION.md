# Zusätzliche Hoverfixture: echte Öffnungsbereitschaft

Der tatsächliche frische Rootlauf auf Build080346, run080436-45dae70f, ist mit einem Timeout in WaitForIntegrity der neuen Hoverfixture fehlgeschlagen. Die Originale bleiben erhalten. Das ist ein Fixture-Befund: MainWindow bindet MainWindow_Opened im Konstruktor (MainWindow.axaml.cs:113) und startet CheckIntegrityAsync erst in diesem Ereignis (131–135). Die neu konstruierte Hoverfixture hatte Show nicht aufgerufen.

Die eng begrenzte Korrektur ruft am eigenen Hoverwindow Show vor dem unveränderten WaitForIntegrity auf. Nach den Assertions werden diese eigenen Fenster Close und Dispose unterzogen; die vorhandene unabhängige Finally-Bereinigung bleibt. Kein produktiver Integritätscheck, Statusgate oder Timeout wurde geändert. Beide Produktdateien bleiben bytegleich.

Neuer Stand:

- KeepVaultMac/Gui/MainWindow.PathsAndDrop.cs: `22457e8b45d4edd1bf9512cce54ebb3bf57e2e857043e9ee8684e785474a459e`
- KeepVaultMac/Gui/MainWindow.StorageAccess.cs: `62517b3d5072db57d19591102692a3502ea8b92417227b710f05436d996cf655`
- KeepVaultMac.Tests/WindowDisposeRev12Tests.cs: `210829407ea2e9c5b90004a220e3c1734e74f911254b6d53da42f6950689ccc3`

Owned git diff --check ist Exit 0. Die ursprünglichen Quellkarten und der erste Diff bleiben als historische Originale erhalten. Root hat außerdem den zweiten tatsächlichen Fall gui.rev12-storage-transitions am unveränderten Build080346, run080555-a7bef7d0, mit Exit 0/PASS gemeldet. Die korrigierte Hoverfixture benötigt einen neuen gebundenen Lauf. Dieser Reviewer führt keine Builds oder Tests aus.
