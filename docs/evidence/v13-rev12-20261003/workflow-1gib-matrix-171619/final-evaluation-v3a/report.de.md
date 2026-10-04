# Gepinnte 12 × 1 GiB Workflowmatrix

Belegordner: /Users/michael/Developer/GPT-Codex/Kalyna/work/v13-evidence/rev12-development-20261003/workflow-1gib-matrix-pinned-20261003T172229Z-c571f026

Alle zwölf tatsächlichen PASS-Receipts und ihre Quellen-, Binary-, Runlog- und Phasenprofilbindungen sind geprüft.

Je Fall genau ein vollständiger Workflow, null Aufwärmläufe, kein Median. Produktive KDF, Auto, Kompression 5; genau 1.073.741.824 Quelldatenbytes einschließlich Unicode-Text und leerer Datei. Der gesamte übrige payload.bin-Inhalt ist deterministischer öffentlicher SplitMix64-Pseudorandom. Kein Überspringen der Kompression.

Managed Release mit echten Service-/Nativepfaden. Dies ist keine Abnahme der installierten AOT-GUI oder des späteren Releasepakets. Der Recovery-Leistungstest erstellt KPAR2 und prüft intakte Daten; beschädigte Recovery wird durch andere Tests geprüft.

Alle MiB/s in den folgenden Haupttabellen zählen die 1.024 MiB Quelldaten genau einmal. Verschlüsselter Payload, Container, Recovery und mehrfach gelesene Bytes haben eigene Bytebasen. Frische Faktoren und Salts können je Fall andere KDF-Arbeit verursachen; dies ist kein kontrollierter CPU-Skalierungsvergleich.

| Suite | Status | Gesamt s | Gesamt MiB/s | Archiv + Encrypt s | Archiv MiB/s | Decrypt + Extract s | Extract MiB/s | KPAR2 erstellen s | KPAR2 intakt prüfen s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Standard | PASS | 1484,061 | 0,689999 | 690,033 | 1,483987 | 754,894 | 1,356481 | 26,451 | 10,821 |
| XChaCha über AES | PASS | 1451,344 | 0,705553 | 685,072 | 1,494734 | 726,741 | 1,409029 | 26,609 | 11,119 |
| Gemischte Kaskade | PASS | 1436,124 | 0,713030 | 669,453 | 1,529607 | 727,863 | 1,406859 | 26,134 | 10,929 |
| Paranoia | PASS | 1461,957 | 0,700431 | 679,694 | 1,506561 | 737,506 | 1,388463 | 30,004 | 12,881 |
| Threefish 1024 | PASS | 1439,163 | 0,711525 | 672,014 | 1,523777 | 726,550 | 1,409400 | 27,380 | 11,472 |
| Kalyna 512/512 | PASS | 1449,198 | 0,706597 | 671,382 | 1,525213 | 737,129 | 1,389173 | 27,371 | 11,508 |
| SHACAL2 512 | PASS | 1432,726 | 0,714721 | 669,858 | 1,528681 | 724,327 | 1,413726 | 25,991 | 10,779 |
| MARS 448 | PASS | 1440,971 | 0,710632 | 670,244 | 1,527801 | 731,372 | 1,400109 | 26,502 | 11,013 |
| AES 256 | PASS | 1626,111 | 0,629723 | 727,577 | 1,407412 | 858,216 | 1,193173 | 27,043 | 11,260 |
| Camellia 256 | PASS | 1539,579 | 0,665117 | 700,238 | 1,462361 | 801,025 | 1,278361 | 25,619 | 10,688 |
| Serpent 256 | PASS | 1582,393 | 0,647121 | 771,937 | 1,326532 | 770,406 | 1,329169 | 26,931 | 11,266 |
| XChaCha20-Poly1305 | PASS | 1649,761 | 0,620696 | 740,047 | 1,383697 | 867,645 | 1,180206 | 28,348 | 11,603 |

Diese Servicezeiten sind separat gestoppte Operationen. Kleine Verwaltungsschritte zwischen den Operationen gehören zur vollständigen Workflowzeit und zu den unten abgegrenzten Makrointervallen.

| Suite | Containerhash s | Original-/Struktur-/Hashvergleich s | Fixturecleanup Service s | RAM-Zulassung + Snapshot Makro s | Snapshot Service s | Setup s | Faktorvorbereitung s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Standard | 0,521586 | 1,266823 | 0,052862 | 0,008057 | 0,007189 | 1,061429 | 0,079080 |
| XChaCha über AES | 0,512569 | 1,232337 | 0,036001 | 0,008535 | 0,007577 | 1,021277 | 0,092103 |
| Gemischte Kaskade | 0,500243 | 1,189089 | 0,034988 | 0,008390 | 0,007453 | 1,056744 | 0,089517 |
| Paranoia | 0,519997 | 1,274679 | 0,055748 | 0,008425 | 0,007482 | 1,055373 | 0,100404 |
| Threefish 1024 | 0,502756 | 1,187361 | 0,033923 | 0,008569 | 0,007600 | 1,061899 | 0,084535 |
| Kalyna 512/512 | 0,511861 | 1,235642 | 0,038592 | 0,008295 | 0,007397 | 1,082630 | 0,080653 |
| SHACAL2 512 | 0,507758 | 1,184392 | 0,056282 | 0,008424 | 0,007473 | 1,046022 | 0,091156 |
| MARS 448 | 0,510435 | 1,256011 | 0,053680 | 0,008402 | 0,007484 | 1,030380 | 0,081213 |
| AES 256 | 0,521495 | 1,413257 | 0,051052 | 0,008721 | 0,007716 | 1,138942 | 0,089232 |
| Camellia 256 | 0,519704 | 1,397177 | 0,064921 | 0,009597 | 0,008547 | 1,105747 | 0,102735 |
| Serpent 256 | 0,524022 | 1,262447 | 0,042651 | 0,010215 | 0,008988 | 1,113785 | 0,105198 |
| XChaCha20-Poly1305 | 0,526409 | 1,488029 | 0,073758 | 0,008472 | 0,007524 | 1,065074 | 0,091457 |

RAM-Zulassung, Originalsnapshot und Verwaltung sind gemeinsam gemessen. Die Differenz zum Snapshot-Servicezeitwert ist keine isoliert gemessene RAM-Wartezeit. Weitere KDF-/MAC-Speicherzulassungen liegen innerhalb späterer Operationen. Setup und Faktorvorbereitung liegen vor dem Workflowtimer.

## Acht vollständige Makrointervalle

Nur diese acht zusammenhängenden äußeren Wandzeitintervalle teilen die Gesamtzeit vollständig auf. Die Prozentwerte beziehen sich auf dieselbe vollständige Workflow-Wandzeit; Rundungen können die angezeigte Summe geringfügig verändern. Sie sind keine vollständige interne parallele Critical-Path-Analyse.

| Suite | RAM-Zulassung + Originalsnapshot | Archivieren + Verschlüsseln | Zusätzlicher Containerhash | KPAR2 erstellen | Intaktes KPAR2 prüfen | Entschlüsseln + Entpacken | Originalvergleich + Struktur/Hashes | Eigene Ressourcen + Testbaum bereinigen | Summe % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Standard | 0,0005 % | 46,4964 % | 0,0351 % | 1,7823 % | 0,7292 % | 50,8668 % | 0,0854 % | 0,0042 % | 100,0000 % |
| XChaCha über AES | 0,0006 % | 47,2027 % | 0,0353 % | 1,8334 % | 0,7661 % | 50,0737 % | 0,0849 % | 0,0033 % | 100,0000 % |
| Gemischte Kaskade | 0,0006 % | 46,6154 % | 0,0348 % | 1,8198 % | 0,7610 % | 50,6824 % | 0,0828 % | 0,0032 % | 100,0000 % |
| Paranoia | 0,0006 % | 46,4922 % | 0,0356 % | 2,0523 % | 0,8811 % | 50,4465 % | 0,0872 % | 0,0046 % | 100,0000 % |
| Threefish 1024 | 0,0006 % | 46,6950 % | 0,0349 % | 1,9025 % | 0,7971 % | 50,4842 % | 0,0825 % | 0,0032 % | 100,0000 % |
| Kalyna 512/512 | 0,0006 % | 46,3279 % | 0,0353 % | 1,8887 % | 0,7941 % | 50,8646 % | 0,0853 % | 0,0035 % | 100,0000 % |
| SHACAL2 512 | 0,0006 % | 46,7543 % | 0,0354 % | 1,8141 % | 0,7523 % | 50,5559 % | 0,0827 % | 0,0048 % | 100,0000 % |
| MARS 448 | 0,0006 % | 46,5135 % | 0,0354 % | 1,8392 % | 0,7643 % | 50,7555 % | 0,0872 % | 0,0044 % | 100,0000 % |
| AES 256 | 0,0005 % | 44,7435 % | 0,0321 % | 1,6631 % | 0,6924 % | 52,7772 % | 0,0869 % | 0,0043 % | 100,0000 % |
| Camellia 256 | 0,0006 % | 45,4825 % | 0,0338 % | 1,6640 % | 0,6942 % | 52,0288 % | 0,0908 % | 0,0052 % | 100,0000 % |
| Serpent 256 | 0,0006 % | 48,7831 % | 0,0331 % | 1,7019 % | 0,7120 % | 48,6862 % | 0,0798 % | 0,0034 % | 100,0000 % |
| XChaCha20-Poly1305 | 0,0005 % | 44,8579 % | 0,0319 % | 1,7183 % | 0,7033 % | 52,5922 % | 0,0902 % | 0,0056 % | 100,0000 % |

### Außenintervalle: Standard

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0080571 | 0,0080571 | 0,000543 |
| Archivieren + Verschlüsseln | 0,0080571 | 690,0433642 | 690,0353071 | 46,496429 |
| Zusätzlicher Containerhash | 690,0433642 | 690,5649533 | 0,5215891 | 0,035146 |
| KPAR2 erstellen | 690,5649533 | 717,0158140 | 26,4508607 | 1,782330 |
| Intaktes KPAR2 prüfen | 717,0158140 | 727,8371772 | 10,8213632 | 0,729172 |
| Entschlüsseln + Entpacken | 727,8371772 | 1482,7315754 | 754,8943982 | 50,866809 |
| Originalvergleich + Struktur/Hashes | 1482,7315754 | 1483,9984002 | 1,2668248 | 0,085362 |
| Eigene Ressourcen + Testbaum bereinigen | 1483,9984002 | 1484,0608536 | 0,0624534 | 0,004208 |
| Summe / vollständiger Workflow | 0,0000000 | 1484,0608536 | 1484,0608536 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1484,0481640 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: XChaCha über AES

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0085350 | 0,0085350 | 0,000588 |
| Archivieren + Verschlüsseln | 0,0085350 | 685,0821520 | 685,0736170 | 47,202691 |
| Zusätzlicher Containerhash | 685,0821520 | 685,5947235 | 0,5125715 | 0,035317 |
| KPAR2 erstellen | 685,5947235 | 712,2038801 | 26,6091566 | 1,833414 |
| Intaktes KPAR2 prüfen | 712,2038801 | 723,3227247 | 11,1188446 | 0,766107 |
| Entschlüsseln + Entpacken | 723,3227247 | 1450,0641640 | 726,7414393 | 50,073672 |
| Originalvergleich + Struktur/Hashes | 1450,0641640 | 1451,2965025 | 1,2323385 | 0,084910 |
| Eigene Ressourcen + Testbaum bereinigen | 1451,2965025 | 1451,3444021 | 0,0478996 | 0,003300 |
| Summe / vollständiger Workflow | 0,0000000 | 1451,3444021 | 1451,3444021 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1451,3293902 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: Gemischte Kaskade

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0083900 | 0,0083900 | 0,000584 |
| Archivieren + Verschlüsseln | 0,0083900 | 669,4632798 | 669,4548898 | 46,615389 |
| Zusätzlicher Containerhash | 669,4632798 | 669,9635247 | 0,5002449 | 0,034833 |
| KPAR2 erstellen | 669,9635247 | 696,0975900 | 26,1340653 | 1,819764 |
| Intaktes KPAR2 prüfen | 696,0975900 | 707,0262091 | 10,9286191 | 0,760980 |
| Entschlüsseln + Entpacken | 707,0262091 | 1434,8889381 | 727,8627290 | 50,682435 |
| Originalvergleich + Struktur/Hashes | 1434,8889381 | 1436,0780289 | 1,1890908 | 0,082799 |
| Eigene Ressourcen + Testbaum bereinigen | 1436,0780289 | 1436,1242210 | 0,0461921 | 0,003216 |
| Summe / vollständiger Workflow | 0,0000000 | 1436,1242210 | 1436,1242210 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1436,1099436 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: Paranoia

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0084249 | 0,0084249 | 0,000576 |
| Archivieren + Verschlüsseln | 0,0084249 | 679,7042825 | 679,6958576 | 46,492197 |
| Zusätzlicher Containerhash | 679,7042825 | 680,2242823 | 0,5199998 | 0,035569 |
| KPAR2 erstellen | 680,2242823 | 710,2279417 | 30,0036594 | 2,052294 |
| Intaktes KPAR2 prüfen | 710,2279417 | 723,1088009 | 12,8808592 | 0,881070 |
| Entschlüsseln + Entpacken | 723,1088009 | 1460,6149883 | 737,5061874 | 50,446508 |
| Originalvergleich + Struktur/Hashes | 1460,6149883 | 1461,8896700 | 1,2746817 | 0,087190 |
| Eigene Ressourcen + Testbaum bereinigen | 1461,8896700 | 1461,9568625 | 0,0671925 | 0,004596 |
| Summe / vollständiger Workflow | 0,0000000 | 1461,9568625 | 1461,9568625 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1461,9423011 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: Threefish 1024

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0085692 | 0,0085692 | 0,000595 |
| Archivieren + Verschlüsseln | 0,0085692 | 672,0250840 | 672,0165148 | 46,694963 |
| Zusätzlicher Containerhash | 672,0250840 | 672,5278424 | 0,5027584 | 0,034934 |
| KPAR2 erstellen | 672,5278424 | 699,9075296 | 27,3796872 | 1,902473 |
| Intaktes KPAR2 prüfen | 699,9075296 | 711,3792360 | 11,4717064 | 0,797110 |
| Entschlüsseln + Entpacken | 711,3792360 | 1437,9296018 | 726,5503658 | 50,484239 |
| Originalvergleich + Struktur/Hashes | 1437,9296018 | 1439,1169642 | 1,1873624 | 0,082504 |
| Eigene Ressourcen + Testbaum bereinigen | 1439,1169642 | 1439,1627593 | 0,0457951 | 0,003182 |
| Summe / vollständiger Workflow | 0,0000000 | 1439,1627593 | 1439,1627593 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1439,1477339 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: Kalyna 512/512

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0082950 | 0,0082950 | 0,000572 |
| Archivieren + Verschlüsseln | 0,0082950 | 671,3919686 | 671,3836736 | 46,327931 |
| Zusätzlicher Containerhash | 671,3919686 | 671,9038317 | 0,5118631 | 0,035320 |
| KPAR2 erstellen | 671,9038317 | 699,2751075 | 27,3712758 | 1,888718 |
| Intaktes KPAR2 prüfen | 699,2751075 | 710,7834427 | 11,5083352 | 0,794117 |
| Entschlüsseln + Entpacken | 710,7834427 | 1447,9127182 | 737,1292755 | 50,864619 |
| Originalvergleich + Struktur/Hashes | 1447,9127182 | 1449,1483622 | 1,2356440 | 0,085264 |
| Eigene Ressourcen + Testbaum bereinigen | 1449,1483622 | 1449,1984745 | 0,0501123 | 0,003458 |
| Summe / vollständiger Workflow | 0,0000000 | 1449,1984745 | 1449,1984745 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1449,1838513 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: SHACAL2 512

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0084237 | 0,0084237 | 0,000588 |
| Archivieren + Verschlüsseln | 0,0084237 | 669,8690075 | 669,8605838 | 46,754257 |
| Zusätzlicher Containerhash | 669,8690075 | 670,3767675 | 0,5077600 | 0,035440 |
| KPAR2 erstellen | 670,3767675 | 696,3676269 | 25,9908594 | 1,814084 |
| Intaktes KPAR2 prüfen | 696,3676269 | 707,1467153 | 10,7790884 | 0,752348 |
| Entschlüsseln + Entpacken | 707,1467153 | 1431,4739123 | 724,3271970 | 50,555864 |
| Originalvergleich + Struktur/Hashes | 1431,4739123 | 1432,6583055 | 1,1843932 | 0,082667 |
| Eigene Ressourcen + Testbaum bereinigen | 1432,6583055 | 1432,7263865 | 0,0680810 | 0,004752 |
| Summe / vollständiger Workflow | 0,0000000 | 1432,7263865 | 1432,7263865 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1432,7114236 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: MARS 448

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0084021 | 0,0084021 | 0,000583 |
| Archivieren + Verschlüsseln | 0,0084021 | 670,2546758 | 670,2462737 | 46,513512 |
| Zusätzlicher Containerhash | 670,2546758 | 670,7651133 | 0,5104375 | 0,035423 |
| KPAR2 erstellen | 670,7651133 | 697,2669162 | 26,5018029 | 1,839163 |
| Intaktes KPAR2 prüfen | 697,2669162 | 708,2801063 | 11,0131901 | 0,764289 |
| Entschlüsseln + Entpacken | 708,2801063 | 1439,6516634 | 731,3715571 | 50,755462 |
| Originalvergleich + Struktur/Hashes | 1439,6516634 | 1440,9076769 | 1,2560135 | 0,087164 |
| Eigene Ressourcen + Testbaum bereinigen | 1440,9076769 | 1440,9711232 | 0,0634463 | 0,004403 |
| Summe / vollständiger Workflow | 0,0000000 | 1440,9711232 | 1440,9711232 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1440,9582613 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: AES 256

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0087205 | 0,0087205 | 0,000536 |
| Archivieren + Verschlüsseln | 0,0087205 | 727,5875825 | 727,5788620 | 44,743499 |
| Zusätzlicher Containerhash | 727,5875825 | 728,1090843 | 0,5215018 | 0,032070 |
| KPAR2 erstellen | 728,1090843 | 755,1525009 | 27,0434166 | 1,663073 |
| Intaktes KPAR2 prüfen | 755,1525009 | 766,4121906 | 11,2596897 | 0,692431 |
| Entschlüsseln + Entpacken | 766,4121906 | 1624,6282360 | 858,2160454 | 52,777218 |
| Originalvergleich + Struktur/Hashes | 1624,6282360 | 1626,0415043 | 1,4132683 | 0,086911 |
| Eigene Ressourcen + Testbaum bereinigen | 1626,0415043 | 1626,1107953 | 0,0692910 | 0,004261 |
| Summe / vollständiger Workflow | 0,0000000 | 1626,1107953 | 1626,1107953 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1626,0891448 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: Camellia 256

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0095967 | 0,0095967 | 0,000623 |
| Archivieren + Verschlüsseln | 0,0095967 | 700,2494046 | 700,2398079 | 45,482537 |
| Zusätzlicher Containerhash | 700,2494046 | 700,7691156 | 0,5197110 | 0,033757 |
| KPAR2 erstellen | 700,7691156 | 726,3882457 | 25,6191301 | 1,664034 |
| Intaktes KPAR2 prüfen | 726,3882457 | 737,0760886 | 10,6878429 | 0,694205 |
| Entschlüsseln + Entpacken | 737,0760886 | 1538,1015441 | 801,0254555 | 52,028848 |
| Originalvergleich + Struktur/Hashes | 1538,1015441 | 1539,4987294 | 1,3971853 | 0,090751 |
| Eigene Ressourcen + Testbaum bereinigen | 1539,4987294 | 1539,5794674 | 0,0807380 | 0,005244 |
| Summe / vollständiger Workflow | 0,0000000 | 1539,5794674 | 1539,5794674 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1539,5602741 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: Serpent 256

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0102151 | 0,0102151 | 0,000646 |
| Archivieren + Verschlüsseln | 0,0102151 | 771,9499947 | 771,9397796 | 48,783062 |
| Zusätzlicher Containerhash | 771,9499947 | 772,4740244 | 0,5240297 | 0,033116 |
| KPAR2 erstellen | 772,4740244 | 799,4053681 | 26,9313437 | 1,701938 |
| Intaktes KPAR2 prüfen | 799,4053681 | 810,6712361 | 11,2658680 | 0,711951 |
| Entschlüsseln + Entpacken | 810,6712361 | 1581,0775472 | 770,4063111 | 48,686153 |
| Originalvergleich + Struktur/Hashes | 1581,0775472 | 1582,3399960 | 1,2624488 | 0,079781 |
| Eigene Ressourcen + Testbaum bereinigen | 1582,3399960 | 1582,3930577 | 0,0530617 | 0,003353 |
| Summe / vollständiger Workflow | 0,0000000 | 1582,3930577 | 1582,3930577 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1582,3789110 s und ersetzen diese vollständige Außenpartition nicht.

### Außenintervalle: XChaCha20-Poly1305

| Außenintervall | Start s | Ende s | Dauer s | Anteil % |
| --- | --- | --- | --- | --- |
| RAM-Zulassung + Originalsnapshot | 0,0000000 | 0,0084722 | 0,0084722 | 0,000514 |
| Archivieren + Verschlüsseln | 0,0084722 | 740,0573288 | 740,0488566 | 44,857932 |
| Zusätzlicher Containerhash | 740,0573288 | 740,5837452 | 0,5264164 | 0,031909 |
| KPAR2 erstellen | 740,5837452 | 768,9322694 | 28,3485242 | 1,718341 |
| Intaktes KPAR2 prüfen | 768,9322694 | 780,5350779 | 11,6028085 | 0,703302 |
| Entschlüsseln + Entpacken | 780,5350779 | 1648,1801756 | 867,6450977 | 52,592156 |
| Originalvergleich + Struktur/Hashes | 1648,1801756 | 1649,6682283 | 1,4880527 | 0,090198 |
| Eigene Ressourcen + Testbaum bereinigen | 1649,6682283 | 1649,7614243 | 0,0931960 | 0,005649 |
| Summe / vollständiger Workflow | 0,0000000 | 1649,7614243 | 1649,7614243 | 100,000000 |

Die separat gestoppten Servicezeiten ergeben 1649,7385428 s und ersetzen diese vollständige Außenpartition nicht.

## Aufgezeichnete Energie- und Thermalbedingungen

Die folgenden Launcher-Belege stammen ausschließlich von den Randabfragen vor und nach dem jeweiligen Fall. Die UTC-Werte sind Fallgrenzen; die einzelnen pmset-Abfragen besitzen keine separat gespeicherten Zeitstempel. Daraus folgen kein kontinuierlicher Leistungsverlauf, keine gemessenen Watt, keine durchgängige Energiequelle, keine Temperatur- oder Frequenzmessung und keine nachgewiesene Throttlingfreiheit. Fehlende aufgezeichnete Warnungen beweisen keine konstante Temperatur oder Taktfrequenz. Energiequelle und Akkustand können sich zwischen oder innerhalb der Fälle ändern; die Matrixbedingungen sind dadurch nicht als kontrollierter Energievergleich belegt.

| Suite | Rand | Fallgrenze UTC | pmset -g batt: tatsächliche Ausgabe | pmset -g therm: tatsächliche Ausgabe |
| --- | --- | --- | --- | --- |
| Standard | Vorher | 2026-10-03T17:22:29.668500+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	60%; discharging; 11:40 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Standard | Nachher | 2026-10-03T17:47:15.563465+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	53%; discharging; 6:50 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| XChaCha über AES | Vorher | 2026-10-03T17:47:15.563953+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	53%; discharging; 6:50 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| XChaCha über AES | Nachher | 2026-10-03T18:11:28.786277+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	47%; discharging; 3:21 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Gemischte Kaskade | Vorher | 2026-10-03T18:11:28.786895+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	47%; discharging; 3:21 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Gemischte Kaskade | Nachher | 2026-10-03T18:35:26.779560+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	41%; discharging; 2:57 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Paranoia | Vorher | 2026-10-03T18:35:26.780137+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	41%; discharging; 2:57 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Paranoia | Nachher | 2026-10-03T18:59:50.616957+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	35%; discharging; 2:31 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Threefish 1024 | Vorher | 2026-10-03T18:59:50.617702+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	35%; discharging; 2:31 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Threefish 1024 | Nachher | 2026-10-03T19:23:51.952330+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	29%; discharging; 2:06 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Kalyna 512/512 | Vorher | 2026-10-03T19:23:51.953118+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	29%; discharging; 2:06 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Kalyna 512/512 | Nachher | 2026-10-03T19:48:03.371685+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	23%; discharging; 1:41 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| SHACAL2 512 | Vorher | 2026-10-03T19:48:03.372542+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	23%; discharging; 1:41 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| SHACAL2 512 | Nachher | 2026-10-03T20:11:58.238323+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	18%; discharging; 1:16 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| MARS 448 | Vorher | 2026-10-03T20:11:58.239210+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	18%; discharging; 1:16 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| MARS 448 | Nachher | 2026-10-04T05:11:24.284697+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	8%; charging; (no estimate) present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| AES 256 | Vorher | 2026-10-04T05:11:24.286948+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	8%; charging; (no estimate) present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| AES 256 | Nachher | 2026-10-04T05:38:32.523092+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	31%; charging; (no estimate) present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Camellia 256 | Vorher | 2026-10-04T05:38:32.524217+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	31%; charging; (no estimate) present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Camellia 256 | Nachher | 2026-10-04T06:04:14.517756+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	55%; charging; (no estimate) present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Serpent 256 | Vorher | 2026-10-04T06:04:14.518975+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	55%; charging; (no estimate) present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| Serpent 256 | Nachher | 2026-10-04T06:30:39.330925+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	75%; charging; 1:09 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| XChaCha20-Poly1305 | Vorher | 2026-10-04T06:30:39.332042+00:00 | Now drawing from 'AC Power'  -InternalBattery-0 (id=23461987)	75%; charging; 1:09 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |
| XChaCha20-Poly1305 | Nachher | 2026-10-04T06:58:11.609809+00:00 | Now drawing from 'Battery Power'  -InternalBattery-0 (id=23461987)	74%; discharging; 2:26 remaining present: true  | Note: No thermal warning level has been recorded Note: No performance warning level has been recorded Note: No CPU power status has been recorded  |

| Suite | Beobachtung im Workflowharness |
| --- | --- |
| Standard | NOT OBSERVED by this harness; no power setting was changed |
| XChaCha über AES | NOT OBSERVED by this harness; no power setting was changed |
| Gemischte Kaskade | NOT OBSERVED by this harness; no power setting was changed |
| Paranoia | NOT OBSERVED by this harness; no power setting was changed |
| Threefish 1024 | NOT OBSERVED by this harness; no power setting was changed |
| Kalyna 512/512 | NOT OBSERVED by this harness; no power setting was changed |
| SHACAL2 512 | NOT OBSERVED by this harness; no power setting was changed |
| MARS 448 | NOT OBSERVED by this harness; no power setting was changed |
| AES 256 | NOT OBSERVED by this harness; no power setting was changed |
| Camellia 256 | NOT OBSERVED by this harness; no power setting was changed |
| Serpent 256 | NOT OBSERVED by this harness; no power setting was changed |
| XChaCha20-Poly1305 | NOT OBSERVED by this harness; no power setting was changed |

Das Harnessfeld berichtet seinen eigenen Beobachtungsscope. Es ersetzt nicht die getrennten tatsächlich aufgezeichneten Launcher-Randabfragen. Eine Low-Power-Mode-Einstellung oder ihre Änderung wird durch diese Belege nicht ermittelt.

## CPU und beobachtete Speicher-/Threadgrenzen

CPUzeit ist keine Wandzeit und kann durch mehrere Prozesse/Kerne über der Workflowzeit liegen. Die Managed-CPU enthält native Libraries im gleichen Prozess. Der zweite CPUwert addiert beobachtete ZPAQ-Childzähler und kann deren letztes ungesampletes Intervall verpassen. Beide CPUzähler enden vor dem Fixturecleanup. Es gibt keine separate CPUzeit je KDF-, Cipher- oder MAC-Stufe. Der RSS-Wert stammt aus der gesamten Testgruppe und ist kein isolierter Workflow- oder PMI-Matrixspeicherwert.

| Suite | Managed CPU s | Managed + beobachtetes ZPAQ CPU s | Testgruppe s | Testgruppe Peak RSS MiB | Anfangs-CPUobergrenze | Native Grant min/max | Peak aktive Callbacks |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Standard | 143,569 | 1574,203 | 1485,267 | 1746,000 | 10 | 1/10 | 10 |
| XChaCha über AES | 129,565 | 1529,655 | 1452,526 | 1981,000 | 10 | 1/10 | 10 |
| Gemischte Kaskade | 135,002 | 1519,407 | 1437,328 | 1903,000 | 10 | 1/10 | 10 |
| Paranoia | 269,491 | 1660,896 | 1463,182 | 2289,000 | 10 | 1/10 | 10 |
| Threefish 1024 | 136,496 | 1522,548 | 1440,665 | 2503,000 | 10 | 4/10 | 10 |
| Kalyna 512/512 | 142,301 | 1537,780 | 1450,707 | 2544,000 | 10 | 4/10 | 10 |
| SHACAL2 512 | 128,199 | 1510,899 | 1434,202 | 1874,000 | 10 | 4/10 | 10 |
| MARS 448 | 134,985 | 1524,261 | 1442,402 | 2055,000 | 10 | 4/10 | 10 |
| AES 256 | 127,773 | 1689,392 | 1627,410 | 2061,000 | 10 | 4/10 | 10 |
| Camellia 256 | 164,829 | 1644,512 | 1541,155 | 1590,000 | 10 | 4/10 | 10 |
| Serpent 256 | 147,078 | 1668,946 | 1584,008 | 1999,000 | 10 | 4/10 | 10 |
| XChaCha20-Poly1305 | 140,926 | 1724,040 | 1651,494 | 2275,000 | 10 | 1/10 | 10 |

## Tatsächliche Bytebasen

| Suite | Quelle Bytes | Komprimierter Payload Bytes | Container Bytes | KPAR2 Bytes |
| --- | --- | --- | --- | --- |
| Standard | 1073741824 | 1073838386 | 1073841425 | 163811328 |
| XChaCha über AES | 1073741824 | 1073838386 | 1073841277 | 163811328 |
| Gemischte Kaskade | 1073741824 | 1073838386 | 1073841405 | 163811328 |
| Paranoia | 1073741824 | 1073838386 | 1073842143 | 163811328 |
| Threefish 1024 | 1073741824 | 1073838386 | 1073840327 | 163811328 |
| Kalyna 512/512 | 1073741824 | 1073838386 | 1073840204 | 163811328 |
| SHACAL2 512 | 1073741824 | 1073838386 | 1073840262 | 163811328 |
| MARS 448 | 1073741824 | 1073838386 | 1073840233 | 163811328 |
| AES 256 | 1073741824 | 1073838386 | 1073840212 | 163811328 |
| Camellia 256 | 1073741824 | 1073838386 | 1073840257 | 163811328 |
| Serpent 256 | 1073741824 | 1073838386 | 1073840261 | 163811328 |
| XChaCha20-Poly1305 | 1073741824 | 1073838386 | 1073841269 | 163811328 |

## Verschachtelte Phasendiagnose

Die folgenden Werte summieren beobachtete Wandintervalle über alle Aufrufe und beide Arbeitsrichtungen. Elternhüllen, enthaltene Zweige und parallele Worker überlappen. Sie dürfen weder untereinander noch zusätzlich zur Workflowzeit oder zu Makrointervallen addiert werden. Ihre Bytezähler können denselben Payload wiederholt zählen. Es sind keine CPUzeiten und keine additiven Prozentanteile.

KdfRound1/2 enthalten die zugehörigen Argon2-SHA3-/Skein-Zweige. AEAD bezeichnet die gemeinsame XChaCha20-Poly1305-Stufe einschließlich Tagarbeit; eine isolierte Poly1305-Zeit wurde nicht gemessen. GlobalAuthentication umfasst die globale Authentifizierung mit beiden Container-MACs. Die sieben MAC-Unterwerte enthalten gemeinsame Arbeit beider MACs und sind keine getrennten HMAC-SHA3-/Skein-Zeiten.

### Standard

Test-ID: `performance.rev12-workflow-1gib-standard-auto`; Suite: `StandardCascade`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000166542 | 0 |
| CredentialSkein | 5 | 0,000301291 | 0 |
| KdfPmiDerivation | 5 | 0,000054834 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 6,763148791 | 0 |
| Argon2Sha3Round1 | 5 | 3,511711501 | 0 |
| Argon2SkeinRound1 | 5 | 3,250148666 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,005162750 | 0 |
| ChunkNonce | 130 | 0,001758623 | 0 |
| CipherAes | 130 | 0,060912830 | 2147676772 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 130 | 1,754300912 | 2147676772 |
| CipherThreefish | 130 | 0,985184051 | 2147676772 |
| AeadEncryptAndTag | 65 | 0,409138419 | 1073838386 |
| AeadVerifyAndDecrypt | 65 | 0,782269745 | 1073838386 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,468179126 | 0 |
| VerifiedGlobalBinding | 2 | 8,393783249 | 0 |
| LocalRangeTags | 9225 | 32,152960499 | 9664572825 |
| LocalRangeVerification | 7063 | 21,123908438 | 7396602538 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000226208 |
| Beide MAC-Wurzeln initialisieren | 0,000141501 |
| Authentifizierten logischen Datenstrom einlesen | 4,123702673 |
| Blatt-MAC-Batches berechnen und abwarten | 2,279977960 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002741204 |
| Beide abschließenden Container-Tags erzeugen | 0,000004291 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,022460877 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 630 | 5320 | 0,449190815 | 24,420688080 | 3,676144305 |

Interne Timeline: 4096 erhaltene Einträge, 30195 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `fd0d15f7b7f4a3260ec3a60abbbb40b91bda2b02d21fde145a47ef3ce981679c`; Ausführungsreceipt SHA-256: `5d750047dfa211fbe56701e3ffd3559544af70a71a9da283e2c05bd84a1c4fec`.

### XChaCha über AES

Test-ID: `performance.rev12-workflow-1gib-xchacha-aes-auto`; Suite: `XChaChaOverAes`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000159501 | 0 |
| CredentialSkein | 5 | 0,000311083 | 0 |
| KdfPmiDerivation | 5 | 0,000063668 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 7,805673501 | 0 |
| Argon2Sha3Round1 | 5 | 4,107839249 | 0 |
| Argon2SkeinRound1 | 5 | 3,696449750 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,002477917 | 0 |
| ChunkNonce | 130 | 0,001351669 | 0 |
| CipherAes | 130 | 0,055905037 | 2147676772 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 65 | 0,412958460 | 1073838386 |
| AeadVerifyAndDecrypt | 65 | 0,738482915 | 1073838386 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,057065292 | 0 |
| VerifiedGlobalBinding | 2 | 8,310256542 | 0 |
| LocalRangeTags | 9225 | 32,352725095 | 9664571493 |
| LocalRangeVerification | 7063 | 21,653991988 | 7396601058 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000200875 |
| Beide MAC-Wurzeln initialisieren | 0,000140541 |
| Authentifizierten logischen Datenstrom einlesen | 3,833931503 |
| Blatt-MAC-Batches berechnen und abwarten | 2,160251660 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002587664 |
| Beide abschließenden Container-Tags erzeugen | 0,000004166 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,024175050 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 380 | 3194 | 0,287690305 | 6,761913870 | 1,170350675 |

Interne Timeline: 4096 erhaltene Einträge, 29935 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `ece2846284c18a372527681fcfe065220dd1fe7f39c0f8efd86f9978dc2867e3`; Ausführungsreceipt SHA-256: `896454271a94e249f45065e848dca0d5eedd83466a7421d8dec4034d1db60410`.

### Gemischte Kaskade

Test-ID: `performance.rev12-workflow-1gib-mixed-auto`; Suite: `MixedCascade`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000164292 | 0 |
| CredentialSkein | 5 | 0,000308792 | 0 |
| KdfPmiDerivation | 5 | 0,000055541 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 7,940988459 | 0 |
| Argon2Sha3Round1 | 5 | 4,170770333 | 0 |
| Argon2SkeinRound1 | 5 | 3,768924876 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,002465000 | 0 |
| ChunkNonce | 130 | 0,001518452 | 0 |
| CipherAes | 130 | 0,059754371 | 2147676772 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 130 | 0,985986502 | 2147676772 |
| AeadEncryptAndTag | 65 | 0,406581797 | 1073838386 |
| AeadVerifyAndDecrypt | 65 | 0,749888291 | 1073838386 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,014207749 | 0 |
| VerifiedGlobalBinding | 2 | 8,388739084 | 0 |
| LocalRangeTags | 9225 | 31,612987752 | 9664572645 |
| LocalRangeVerification | 7063 | 21,020307510 | 7396602338 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000202458 |
| Beide MAC-Wurzeln initialisieren | 0,000141334 |
| Authentifizierten logischen Datenstrom einlesen | 3,786676751 |
| Blatt-MAC-Batches berechnen und abwarten | 2,165048091 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002618051 |
| Beide abschließenden Container-Tags erzeugen | 0,000004166 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,023519037 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 505 | 4257 | 0,322809242 | 13,135573865 | 2,064893326 |

Interne Timeline: 4096 erhaltene Einträge, 30065 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `300ae955a3d2030bed64421ab25f748baee7a4efd5d986a1134b1256b0053f82`; Ausführungsreceipt SHA-256: `62dc9b883ea99bb4991053a7bdb249718a12911d941cfa44877e8b4c2bba9e5b`.

### Paranoia

Test-ID: `performance.rev12-workflow-1gib-paranoia-auto`; Suite: `ParanoiaCascade`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000156876 | 0 |
| CredentialSkein | 5 | 0,000339502 | 0 |
| KdfPmiDerivation | 10 | 0,000160794 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 9,259615917 | 0 |
| Argon2Sha3Round1 | 5 | 4,781490041 | 0 |
| Argon2SkeinRound1 | 5 | 4,476755416 | 0 |
| KdfRound2 | 5 | 8,239736833 | 0 |
| Argon2Sha3Round2 | 5 | 4,132467876 | 0 |
| Argon2SkeinRound2 | 5 | 4,106260917 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,002822708 | 0 |
| ChunkNonce | 130 | 0,001743256 | 0 |
| CipherAes | 130 | 0,058187830 | 2147676772 |
| CipherMars | 130 | 1,786741248 | 2147676772 |
| CipherCamellia | 130 | 7,573059165 | 2147676772 |
| CipherSerpent | 130 | 3,065597629 | 2147676772 |
| CipherShacal2 | 130 | 1,425559042 | 2147676772 |
| CipherKalyna | 130 | 1,656510253 | 2147676772 |
| CipherThreefish | 130 | 0,958964878 | 2147676772 |
| AeadEncryptAndTag | 65 | 0,402995210 | 1073838386 |
| AeadVerifyAndDecrypt | 65 | 0,762848334 | 1073838386 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,025345375 | 0 |
| VerifiedGlobalBinding | 2 | 12,140852375 | 0 |
| LocalRangeTags | 9225 | 31,603109437 | 9664579287 |
| LocalRangeVerification | 7063 | 21,014786712 | 7396609718 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000203333 |
| Beide MAC-Wurzeln initialisieren | 0,000142958 |
| Authentifizierten logischen Datenstrom einlesen | 3,816518750 |
| Blatt-MAC-Batches berechnen und abwarten | 2,146164299 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002625864 |
| Beide abschließenden Container-Tags erzeugen | 0,000004374 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,024002074 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 1130 | 9572 | 0,607380825 | 111,410481145 | 15,807179646 |

Interne Timeline: 4096 erhaltene Einträge, 30745 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `bf7272c30529bde8092c8150b34ab7bd982a1d184ea1135492c751c036a2016a`; Ausführungsreceipt SHA-256: `701bb12c15f4f9a2c6edd5097e9da6e262e52ebc1e8a846bd141f576a1437efe`.

### Threefish 1024

Test-ID: `performance.rev12-workflow-1gib-threefish1024-auto`; Suite: `Threefish1024`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000158458 | 0 |
| CredentialSkein | 5 | 0,000302000 | 0 |
| KdfPmiDerivation | 5 | 0,000058624 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 10,562693624 | 0 |
| Argon2Sha3Round1 | 5 | 5,486591373 | 0 |
| Argon2SkeinRound1 | 5 | 5,069826790 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,003145625 | 0 |
| ChunkNonce | 130 | 0,001704374 | 0 |
| CipherAes | 0 | 0,000000000 | 0 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 130 | 0,903030289 | 2147676772 |
| AeadEncryptAndTag | 0 | 0,000000000 | 0 |
| AeadVerifyAndDecrypt | 0 | 0,000000000 | 0 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,046114000 | 0 |
| VerifiedGlobalBinding | 2 | 9,434263625 | 0 |
| LocalRangeTags | 9225 | 31,604202377 | 9664562943 |
| LocalRangeVerification | 7055 | 20,993097037 | 7388202950 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000216458 |
| Beide MAC-Wurzeln initialisieren | 0,000146957 |
| Authentifizierten logischen Datenstrom einlesen | 3,829894999 |
| Blatt-MAC-Batches berechnen und abwarten | 2,145829002 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002609084 |
| Beide abschließenden Container-Tags erzeugen | 0,000004043 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,024590247 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 125 | 1063 | 0,174126859 | 5,628256934 | 0,809001083 |

Interne Timeline: 4096 erhaltene Einträge, 29797 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `bb7aa883a111a786f77f37f7f12e6d97c91f31a8b1254503020990c14bd60bca`; Ausführungsreceipt SHA-256: `09b6d11d2d253ce0e2c01bdb83bb807833a8fce068667e3b46223233b2ef6103`.

### Kalyna 512/512

Test-ID: `performance.rev12-workflow-1gib-kalyna512-512-auto`; Suite: `Kalyna512_512`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000165667 | 0 |
| CredentialSkein | 5 | 0,000311208 | 0 |
| KdfPmiDerivation | 5 | 0,000065624 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 10,581794375 | 0 |
| Argon2Sha3Round1 | 5 | 5,441099583 | 0 |
| Argon2SkeinRound1 | 5 | 5,139342000 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,002665791 | 0 |
| ChunkNonce | 130 | 0,001596671 | 0 |
| CipherAes | 0 | 0,000000000 | 0 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 130 | 1,635448174 | 2147676772 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 0 | 0,000000000 | 0 |
| AeadVerifyAndDecrypt | 0 | 0,000000000 | 0 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,042654833 | 0 |
| VerifiedGlobalBinding | 2 | 9,399305875 | 0 |
| LocalRangeTags | 9225 | 31,623363914 | 9664561836 |
| LocalRangeVerification | 7055 | 21,020769129 | 7388201720 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000209042 |
| Beide MAC-Wurzeln initialisieren | 0,000141875 |
| Authentifizierten logischen Datenstrom einlesen | 3,823367973 |
| Blatt-MAC-Batches berechnen und abwarten | 2,156956670 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002584243 |
| Beide abschließenden Container-Tags erzeugen | 0,000003915 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,023952626 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 125 | 1063 | 0,184597477 | 10,494834702 | 1,469536456 |

Interne Timeline: 4096 erhaltene Einträge, 29797 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `cc56d3e9d8097c7050c2b5993b5492155344dab1772098209cc7c2c49fd68fe4`; Ausführungsreceipt SHA-256: `956c6daf3f376039b7148d5cf8cbb72efe4d47c7c3553a9f037fe4a0f4052acf`.

### SHACAL2 512

Test-ID: `performance.rev12-workflow-1gib-shacal2-512-auto`; Suite: `Shacal2_512`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000162543 | 0 |
| CredentialSkein | 5 | 0,000313499 | 0 |
| KdfPmiDerivation | 5 | 0,000052583 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 7,183749542 | 0 |
| Argon2Sha3Round1 | 5 | 3,753508042 | 0 |
| Argon2SkeinRound1 | 5 | 3,428903251 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,002470125 | 0 |
| ChunkNonce | 130 | 0,001515746 | 0 |
| CipherAes | 0 | 0,000000000 | 0 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 130 | 1,457989422 | 2147676772 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 0 | 0,000000000 | 0 |
| AeadVerifyAndDecrypt | 0 | 0,000000000 | 0 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,037482458 | 0 |
| VerifiedGlobalBinding | 2 | 8,023450832 | 0 |
| LocalRangeTags | 9225 | 31,544452084 | 9664562358 |
| LocalRangeVerification | 7055 | 20,971675283 | 7388202300 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000210042 |
| Beide MAC-Wurzeln initialisieren | 0,000148834 |
| Authentifizierten logischen Datenstrom einlesen | 3,818147849 |
| Blatt-MAC-Batches berechnen und abwarten | 2,156802083 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002615625 |
| Beide abschließenden Container-Tags erzeugen | 0,000003917 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,023694034 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 125 | 1063 | 0,189178580 | 9,143107591 | 1,301967247 |

Interne Timeline: 4096 erhaltene Einträge, 29797 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `31c9d8acf1656c93b59da004235a795435ca0e25446cce4b58c5a1f98f0f291a`; Ausführungsreceipt SHA-256: `ad68e2ecf56694c11e76d552cf1f97148405801d0576f45d64c8be174460c608`.

### MARS 448

Test-ID: `performance.rev12-workflow-1gib-mars448-auto`; Suite: `Mars448`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000169376 | 0 |
| CredentialSkein | 5 | 0,000324123 | 0 |
| KdfPmiDerivation | 5 | 0,000058749 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 8,133372042 | 0 |
| Argon2Sha3Round1 | 5 | 4,221749167 | 0 |
| Argon2SkeinRound1 | 5 | 3,907877125 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,004669667 | 0 |
| ChunkNonce | 130 | 0,001437791 | 0 |
| CipherAes | 0 | 0,000000000 | 0 |
| CipherMars | 130 | 1,808308539 | 2147676772 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 0 | 0,000000000 | 0 |
| AeadVerifyAndDecrypt | 0 | 0,000000000 | 0 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,057136542 | 0 |
| VerifiedGlobalBinding | 2 | 8,454177291 | 0 |
| LocalRangeTags | 9225 | 31,738382671 | 9664562097 |
| LocalRangeVerification | 7055 | 21,128288552 | 7388202010 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000206499 |
| Beide MAC-Wurzeln initialisieren | 0,000141541 |
| Authentifizierten logischen Datenstrom einlesen | 3,828153200 |
| Blatt-MAC-Batches berechnen und abwarten | 2,161376410 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002630283 |
| Beide abschließenden Container-Tags erzeugen | 0,000004292 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,024008501 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 125 | 1063 | 0,186996840 | 11,422018510 | 1,618131043 |

Interne Timeline: 4096 erhaltene Einträge, 29797 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `2712ffab0db3f3d82a613eb37cbc7baf600c55170c63fdde544fcb44de5a337c`; Ausführungsreceipt SHA-256: `49a849c41198cb616fb46f4ef72f3e36892d11b9fd05fb1d10a9c74afd7ba9dc`.

### AES 256

Test-ID: `performance.rev12-workflow-1gib-aes256-auto`; Suite: `Aes256`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000170333 | 0 |
| CredentialSkein | 5 | 0,000306085 | 0 |
| KdfPmiDerivation | 5 | 0,000051625 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 9,173020791 | 0 |
| Argon2Sha3Round1 | 5 | 4,943374542 | 0 |
| Argon2SkeinRound1 | 5 | 4,227939332 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,003142292 | 0 |
| ChunkNonce | 130 | 0,001544383 | 0 |
| CipherAes | 130 | 0,072549667 | 2147676772 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 0 | 0,000000000 | 0 |
| AeadVerifyAndDecrypt | 0 | 0,000000000 | 0 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,272414918 | 0 |
| VerifiedGlobalBinding | 2 | 8,937270375 | 0 |
| LocalRangeTags | 9225 | 32,028810538 | 9664561908 |
| LocalRangeVerification | 7055 | 21,318590586 | 7388201800 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000258543 |
| Beide MAC-Wurzeln initialisieren | 0,000154417 |
| Authentifizierten logischen Datenstrom einlesen | 3,982428865 |
| Blatt-MAC-Batches berechnen und abwarten | 2,218709708 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002720460 |
| Beide abschließenden Container-Tags erzeugen | 0,000003959 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,021360792 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 125 | 1063 | 0,172908944 | 0,315348362 | 0,066367200 |

Interne Timeline: 4096 erhaltene Einträge, 29797 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `0d011060904c9b58c5b2232f69be9e0103c87b0d2315c8a488857066bdacaf66`; Ausführungsreceipt SHA-256: `3d150e68f93fceff0471aeb0819a95ce23df5d2731648c733d01bfb297b84b7b`.

### Camellia 256

Test-ID: `performance.rev12-workflow-1gib-camellia-auto`; Suite: `Camellia256`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000169833 | 0 |
| CredentialSkein | 5 | 0,000334208 | 0 |
| KdfPmiDerivation | 5 | 0,000069666 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 6,469859041 | 0 |
| Argon2Sha3Round1 | 5 | 3,436758875 | 0 |
| Argon2SkeinRound1 | 5 | 3,031584084 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,002851292 | 0 |
| ChunkNonce | 130 | 0,001734546 | 0 |
| CipherAes | 0 | 0,000000000 | 0 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 130 | 7,845463420 | 2147676772 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 0 | 0,000000000 | 0 |
| AeadVerifyAndDecrypt | 0 | 0,000000000 | 0 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,154898750 | 0 |
| VerifiedGlobalBinding | 2 | 7,680662999 | 0 |
| LocalRangeTags | 9225 | 31,642858284 | 9664562313 |
| LocalRangeVerification | 7055 | 21,038400653 | 7388202250 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000218293 |
| Beide MAC-Wurzeln initialisieren | 0,000147708 |
| Authentifizierten logischen Datenstrom einlesen | 3,910545573 |
| Blatt-MAC-Batches berechnen und abwarten | 2,183054327 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002652331 |
| Beide abschließenden Container-Tags erzeugen | 0,000003666 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,020854830 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 125 | 1063 | 0,252678740 | 49,793562531 | 6,961948043 |

Interne Timeline: 4096 erhaltene Einträge, 29797 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `d75b269073a8f1f76b112f1874347021a014ac9091ee364368b981ef34a478ad`; Ausführungsreceipt SHA-256: `b55730df01441b626ad65a8e11a6baa3c77ac968dda9a108fddacd3cff807904`.

### Serpent 256

Test-ID: `performance.rev12-workflow-1gib-serpent-auto`; Suite: `Serpent256`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000174834 | 0 |
| CredentialSkein | 5 | 0,000328208 | 0 |
| KdfPmiDerivation | 5 | 0,000077207 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 9,212593001 | 0 |
| Argon2Sha3Round1 | 5 | 4,935644501 | 0 |
| Argon2SkeinRound1 | 5 | 4,272545500 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,002784916 | 0 |
| ChunkNonce | 130 | 0,001695129 | 0 |
| CipherAes | 0 | 0,000000000 | 0 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 130 | 3,310661458 | 2147676772 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 0 | 0,000000000 | 0 |
| AeadVerifyAndDecrypt | 0 | 0,000000000 | 0 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,262939791 | 0 |
| VerifiedGlobalBinding | 2 | 8,912966541 | 0 |
| LocalRangeTags | 9225 | 31,863786613 | 9664562349 |
| LocalRangeVerification | 7055 | 21,135648902 | 7388202290 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000276792 |
| Beide MAC-Wurzeln initialisieren | 0,000190875 |
| Authentifizierten logischen Datenstrom einlesen | 3,945417996 |
| Blatt-MAC-Batches berechnen und abwarten | 2,251152287 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002773862 |
| Beide abschließenden Container-Tags erzeugen | 0,000004709 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,020163411 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 125 | 1063 | 0,289710241 | 21,129790558 | 2,957516828 |

Interne Timeline: 4096 erhaltene Einträge, 29797 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `35e3af62e56ec6e2b0deabce655724e45a8ec309d375eb3909c24b937fba4525`; Ausführungsreceipt SHA-256: `13dd0c02d9397ddc453db21c29d0194e14623f0f3033c3423f20c2bd0acf02e8`.

### XChaCha20-Poly1305

Test-ID: `performance.rev12-workflow-1gib-xchacha20-poly1305-auto`; Suite: `XChaCha20Poly1305`.

Zugangsdaten und KDF-Parameter:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| CredentialSha3 | 5 | 0,000164833 | 0 |
| CredentialSkein | 5 | 0,000308459 | 0 |
| KdfPmiDerivation | 5 | 0,000060250 | 0 |

KDF-Rundenhüllen mit enthaltenen Argon2-Zweigen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KdfRound1 | 5 | 10,975362583 | 0 |
| Argon2Sha3Round1 | 5 | 5,894800749 | 0 |
| Argon2SkeinRound1 | 5 | 5,075703791 | 0 |
| KdfRound2 | 0 | 0,000000000 | 0 |
| Argon2Sha3Round2 | 0 | 0,000000000 | 0 |
| Argon2SkeinRound2 | 0 | 0,000000000 | 0 |

Kryptostufen und AEAD:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| KeySchedule | 3 | 0,004954916 | 0 |
| ChunkNonce | 130 | 0,001696083 | 0 |
| CipherAes | 0 | 0,000000000 | 0 |
| CipherMars | 0 | 0,000000000 | 0 |
| CipherCamellia | 0 | 0,000000000 | 0 |
| CipherSerpent | 0 | 0,000000000 | 0 |
| CipherShacal2 | 0 | 0,000000000 | 0 |
| CipherKalyna | 0 | 0,000000000 | 0 |
| CipherThreefish | 0 | 0,000000000 | 0 |
| AeadEncryptAndTag | 65 | 0,441368286 | 1073838386 |
| AeadVerifyAndDecrypt | 65 | 0,833162210 | 1073838386 |

Globale MACs und getrennte Bindungs-/Bereichsprüfungen:

| Phase | Aufrufe | Wall-Intervallsumme s | Eigene öffentliche Bytesumme |
| --- | --- | --- | --- |
| GlobalAuthentication | 3 | 6,229800292 | 0 |
| VerifiedGlobalBinding | 2 | 9,675887666 | 0 |
| LocalRangeTags | 9225 | 32,121326325 | 9664571421 |
| LocalRangeVerification | 7063 | 21,452287109 | 7396600978 |

Unterdiagnose der globalen MAC-Arbeit:

| MAC-Teil | Wall-Intervallsumme s |
| --- | --- |
| MAC-Unterschlüssel vorbereiten | 0,000256417 |
| Beide MAC-Wurzeln initialisieren | 0,000148666 |
| Authentifizierten logischen Datenstrom einlesen | 3,935221094 |
| Blatt-MAC-Batches berechnen und abwarten | 2,220173504 |
| Blattresultate geordnet in MAC-Wurzeln einbinden | 0,002734297 |
| Beide abschließenden Container-Tags erzeugen | 0,000004125 |
| MAC-Puffer und MAC-Schlüssel bereinigen | 0,019054379 |

Native Scheduling, ebenfalls überlappende Intervallsummen:

| Batches | Beendete Callbacks | Submission bis Callback s | Callback s | Caller Join s |
| --- | --- | --- | --- | --- |
| 255 | 2131 | 0,363538848 | 6,858103233 | 1,241469209 |

Interne Timeline: 4096 erhaltene Einträge, 29805 ausgelassene Einträge; die Aggregate enthalten später abgeschlossene Intervalle. Ihr Zeitursprung liegt vor der Faktorvorbereitung und ist nicht der Workflowtimer.

Profil SHA-256: `9e1971f6b15f5e6f840992f7cf16e4ba69c7fb1117c2efdef9f0d4e61b23db2f`; Ausführungsreceipt SHA-256: `d596c312208220d7853da3327488142b0c339cb66d25eabaf26f535e947d2959`.

## Administrative Steuerung der Teststarts

Die folgenden unveränderten Belege betreffen ausschließlich den steuernden Matrixparent. Der dokumentierte gezielte SIGSTOP galt nur dessen PID; die aktive Child-Prozessgruppe wurde damit nicht signalisiert. Das ist keine vom Benutzer beauftragte Pause der Aufgabe und kein Produkt- oder Test-PASS. Der Holdbeleg dokumentiert die damalige Beobachtung und Handlung, keine heutige Prozess- oder Stromlage und keine kontinuierliche Signalüberwachung. Es wird keine ununterbrochene Child-Ausführung über einen ungemessenen Gesamtzeitraum daraus bewiesen.

Ein administrativer Parentstopp ist keine Pausierung des gemessenen Child-Wandzeittimers. Weder Haltdauer noch Wartezeiten werden nachträglich aus den acht Workflowintervallen, CPUzählern oder Durchsatznennern herausgerechnet. Fallgrenzen des Launchers können Verwaltungswartezeit umfassen und sind nicht die im Test gemessene Workflow-Wandzeit. Ein Resume gilt nur als dokumentiert, wenn ein eigener neuer an den ursprünglichen Hold gebundener Receipt gelesen wurde.

Administrativer Belegstatus: `HOLD AND SEPARATE RESUME RECORDED`.

| Art | Belegname | Original SHA-256 | Öffentliche Kopie SHA-256 |
| --- | --- | --- | --- |
| HOLD | administrative-power-hold-20261003T2021.json | 3dfb5e7a14a6744fc32527e889ed0d1f0965324dbc811dd0f05b221aa2c6cbaf | 3dfb5e7a14a6744fc32527e889ed0d1f0965324dbc811dd0f05b221aa2c6cbaf |
| RESUME | administrative-power-resume-20261004T051124Z.json | 3787fb2fcab86665235b8d73703fc118c2090b467a2724bbb266decf53ca3064 | 3787fb2fcab86665235b8d73703fc118c2090b467a2724bbb266decf53ca3064 |

### HOLD: administrative-power-hold-20261003T2021.json

Originalpfad: `/Users/michael/Developer/GPT-Codex/Kalyna/work/v13-evidence/rev12-development-20261003/workflow-1gib-matrix-pinned-20261003T172229Z-c571f026/administrative-power-hold-20261003T2021.json`.

Gespeicherte Felder des unveränderten Receipts, ohne erfundene Ergänzungen:

```json
{
  "recordedUtc": "2026-10-03T20:22:02.704230+00:00",
  "signalRequestedUtc": "2026-10-03T20:22:02.702287+00:00",
  "parentPid": 98746,
  "parentCommand": "/opt/homebrew/Cellar/python@3.14/3.14.5/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python work/v13-evidence/rev12-development-20261003/run-workflow-1gib-matrix-pinned.py --build /Users/michael/Developer/GPT-Codex/Kalyna/work/v13-evidence/rev12-development-20261003/build-20261003T171619Z",
  "parentStateAfterSignal": "Ts",
  "activeTestId": "performance.rev12-workflow-1gib-mars448-auto",
  "uninterruptedChildProcessGroup": 1792,
  "battery": "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=23461987)\t15%; discharging; 1:04 remaining present: true\n",
  "action": "Only the owned administrative parent was stopped. Active measured test and its native children continue uninterrupted. Future cases await verified AC power. No product source or matrix outcome edited.",
  "resumedUtc": null
}
```

### RESUME: administrative-power-resume-20261004T051124Z.json

Originalpfad: `/Users/michael/Developer/GPT-Codex/Kalyna/work/v13-evidence/rev12-development-20261003/workflow-1gib-matrix-pinned-20261003T172229Z-c571f026/administrative-power-resume-20261004T051124Z.json`.

Gespeicherte Felder des unveränderten Receipts, ohne erfundene Ergänzungen:

```json
{
  "holdReceipt": "administrative-power-hold-20261003T2021.json",
  "holdSha256": "3dfb5e7a14a6744fc32527e889ed0d1f0965324dbc811dd0f05b221aa2c6cbaf",
  "parentPid": 98746,
  "resumedUtc": "2026-10-04T05:11:24.116154+00:00",
  "battery": "Now drawing from 'AC Power'\n -InternalBattery-0 (id=23461987)\t8%; charging; (no estimate) present: true\n",
  "parentCommandBefore": "501 Ts   /opt/homebrew/Cellar/python@3.14/3.14.5/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python work/v13-evidence/rev12-development-20261003/run-workflow-1gib-matrix-pinned.py --build /Users/michael/Developer/GPT-Codex/Kalyna/work/v13-evidence/rev12-development-20261003/build-20261003T171619Z",
  "parentStateAfter": "501 Us   /opt/homebrew/Cellar/python@3.14/3.14.5/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python work/v13-evidence/rev12-development-20261003/run-workflow-1gib-matrix-pinned.py --build /Users/michael/Developer/GPT-Codex/Kalyna/work/v13-evidence/rev12-development-20261003/build-20261003T171619Z",
  "awakeReceipt": "awake-assertion-resume-20261004T051124Z.json",
  "freshAwakePid": 4395,
  "sourceBinaryBuildMetadataDriverVerified": true,
  "remainingOwnedMarsProcessesBeforeResume": [],
  "ownedWorkflowFixturesBeforeResume": [],
  "scope": "SIGCONT directed only at original held parent after actual AC observation and complete frozen-input verification. No measured child signaled or restarted; original hold receipt retained unchanged."
}
```

## Belegstatus und Bindung

| Test-ID | Tatsächlicher Status | Gestartet |
| --- | --- | --- |
| performance.rev12-workflow-1gib-standard-auto | PASS | ja |
| performance.rev12-workflow-1gib-xchacha-aes-auto | PASS | ja |
| performance.rev12-workflow-1gib-mixed-auto | PASS | ja |
| performance.rev12-workflow-1gib-paranoia-auto | PASS | ja |
| performance.rev12-workflow-1gib-threefish1024-auto | PASS | ja |
| performance.rev12-workflow-1gib-kalyna512-512-auto | PASS | ja |
| performance.rev12-workflow-1gib-shacal2-512-auto | PASS | ja |
| performance.rev12-workflow-1gib-mars448-auto | PASS | ja |
| performance.rev12-workflow-1gib-aes256-auto | PASS | ja |
| performance.rev12-workflow-1gib-camellia-auto | PASS | ja |
| performance.rev12-workflow-1gib-serpent-auto | PASS | ja |
| performance.rev12-workflow-1gib-xchacha20-poly1305-auto | PASS | ja |

Die Bindung gilt für die erhaltenen Messbelege und den damals gebauten Stand. Aktuell geänderte Quellen werden durch diesen lesenden Auswerter nicht neu getestet. Hashbindung ist kein externes Sicherheitsaudit.

```json
{
  "build": "/Users/michael/Developer/GPT-Codex/Kalyna/work/v13-evidence/rev12-development-20261003/build-20261003T171619Z",
  "buildResultSha256": "5ea8c15ee184bcd9d0ef98c8c8b3438f9db2323260bf0ecac73e89fca487ca93",
  "sourceInputsSha256": "8d52fc5413ba8b38bb6db6fc56b2555416e91780550470b641b40f7bd9ce5dab",
  "binaryInputsSha256": "daef4ed1a94c8a3ef3cbe229ce2e3dbae0608d93668217d906c4571b5c28f069",
  "buildMetadataSha256": "a7ff7159f7787ead52667854b4cffd5966c0f7aa3d0bd66cfdb569dced211311",
  "driverSha256": "d415c9e3316327099b89e0cc3bab8cde5020f0ad272d5d5e586ecc6d21f6407e",
  "launcherSha256": "da653011f15d78826dc6cdd963491a313dade2769e5e4ec27a8ea16ab9a2a8d5",
  "productAssemblySha256": "71709145c0a57de1631ac7e5ff3db1499ef94fbc42a239201c773e3c7ef29655",
  "testAssemblySha256": "9ddcb0acec6c8264c3f430341896194b2625e56387e78277820ec9660c71aefe"
}
```
