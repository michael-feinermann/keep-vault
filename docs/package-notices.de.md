# Erläuterungen zu den ausgelieferten Lizenzhinweisen

[Deutsch](package-notices.de.md) · [English](package-notices.en.md) · [Dokumentationsverzeichnis](README.md)

Diese Seite übersetzt die eigenen Begleittexte der Paket-Lizenzhinweise. Die vollständigen Lizenzbedingungen und Copyright-Erklärungen bleiben unverändert in den verlinkten Originaldateien und im ausgelieferten Paket. Die Übersetzung ändert keine Nutzungsbedingungen. Die [Installationsanleitung des Pakets](../KeepVaultMac/Packaging/INSTALLATION.txt) ist bereits vollständig deutsch und englisch.

## Drittsoftware im v12-Paket

Original: [ThirdPartyNoticesHeader.txt](../KeepVaultMac/Packaging/ThirdPartyNoticesHeader.txt).

Diese Distribution enthält Software Dritter. Die vollständigen Hinweise sind Teil der Distribution und müssen jeder binären Kopie beiliegen. Der Release-Build hängt die unveränderten Lizenz- und Drittanbieterhinweise aus genau den festgelegten Paketen und eingebundenen Quellrevisionen an, mit denen die Anwendung erstellt wurde. Vor und nach jedem Anhängen erfolgt eine Prüfung gegen einen fest verankerten SHA-256-Wert.

Die folgenden Komponenten fallen unter den gemeinsam beigefügten MIT-Lizenztext:

- Avalonia 12.1.1 und seine Laufzeitkomponenten. Copyright 2013-2026 The AvaloniaUI Project.
- PDFsharp 6.2.4. Copyright 2005-2026 empira Software GmbH, Troisdorf, Germany.
- MicroCom.Runtime 0.11.6. Copyright 2021 Nikita Tsukanov.
- Tmds.DBus.Protocol 0.94.1. Copyright Tom Deseyn.
- Microsoft.Extensions.DependencyInjection.Abstractions 8.0.2.
- Microsoft.Extensions.Logging.Abstractions 8.0.3.
- System.Security.Cryptography.Pkcs 8.0.1. Copyright .NET Foundation and Contributors.

Die Schrift Inter trägt den Hinweis Copyright 2016 The Inter Project Authors ([Projekt](https://github.com/rsms/inter)) und wird unter SIL Open Font License, Version 1.1, verteilt. Der vollständige englische OFL-Text vom 26. Februar 2007 steht im Original.

Die Autoren stellen die Skein-Hashfunktion, die Threefish-Blockchiffre und ihren Quellcode gemeinfrei bereit. Die enthaltenen Portabilitätsheader besitzen gesonderte Brian-Gladman-Hinweise von 1998-2006 beziehungsweise 2003. Ihre vollständigen Bedingungen, alternative GPL-Regelung und Haftungsausschlüsse bleiben im Original enthalten.

Die Argon2-Referenzimplementierung wird unter ihrer CC0-1.0-Option verwendet. Für die ML-DSA-Referenzimplementierung in den Release-Werkzeugen gilt deren CC0-Option. Die Autoren verzichten im rechtlich zulässigen Umfang auf Urheber- und verwandte Rechte. Ihre Quelldistributionen bleiben mit der getaggten Quellveröffentlichung verfügbar.

## Mitgelieferte Offline-Daten zur Passwortanalyse

Original: [PasswordModelNoticesHeader.txt](../KeepVaultMac/Packaging/PasswordModelNoticesHeader.txt).

Die signierte Anwendung enthält öffentliche Wortlisten, nach Häufigkeit geordnete Wortdaten, Namen und eine begrenzte Passwortblockliste. Diese Daten dienen ausschließlich der Auswahl von Zugangsdaten für neue Archive. Netzwerkabfragen oder Datendownloads zur Laufzeit sind nicht erforderlich.

Das beigefügte Manifest dokumentiert ursprüngliche Autoren und Projekte, unveränderliche Quellrevisionen soweit verfügbar, Hashwerte der Original- und abgeleiteten Dateien, Transformationen, Eintragszahlen und Lizenzen. Ihm folgen die vollständigen erforderlichen Lizenz- und Attributionshinweise. Interpretation und Grenzen des Modells sind vollständig auf [Deutsch](password-model/README.de.md) und [Englisch](password-model/README.en.md) beschrieben; das eingebettete Original liegt unter `KalynaArchiver/Resources/PasswordModel/README.md`.

Attribution:

- Electronic Frontier Foundation: EFF Long Wordlist, CC BY 4.0.
- dys2p: deutsche Wortliste de-7776-v1, CC0 1.0.
- Bitcoin BIPs und Trezor python-mnemonic: bytegleiche englische BIP39-Liste, verteilt mit der MIT-Lizenz von Trezor.
- zxcvbn-ts und OPUS: englische und deutsche häufigkeitsgeordnete Wortdaten, ODC-BY 1.0; deutsche Vornamen unter der MIT-Lizenz von zxcvbn-ts.
- Dropbox zxcvbn: ausgewählte öffentliche Passwortkandidaten und englische Namenslisten, MIT-Lizenz.
- Keep Vault: kleine selbst zusammengestellte Aufzählungen öffentlicher Beispielformulierungen und Blocklisteneinträge, MIT-Lizenz gemäß Quellveröffentlichung.

Etwaige Transformationen werden je Datei getrennt ausgewiesen. Diese endlichen Datenbestände sind keine vollständige Datenbank kompromittierter Passwörter. Ihre Aufnahme bedeutet weder eine Unterstützung durch ihre Autoren noch eine empirische Garantie der Passwortentropie.
