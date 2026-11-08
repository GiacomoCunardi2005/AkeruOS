# Mappa ISO della lista diagnostica — firmware 1.1

Data 2026-11-04. La tabella seguente rappresenta la lista statica `DebugModeISO` nel campione V1.1 e la conversione software, **non un limite fisico verificato del sensore**. I 24 record originali (Exit, Auto e 22 voci numeriche) sono stati verificati nei payload. Il [banco scanner → controllo → conferma → setter](../Python_Trace_Scripts/s33_verify_key_scanner_control_confirm_cpu.py) ha provato tutte le posizioni con due ordini callback: [48/48 PASS](../Risultati/GUI_S33/key_scanner_control_confirm_cpu_20261104T111720669336Z/verified_evidence.json). Input, ordine, controllo e posizione sono sintetici; la posizione è imposta, non navigata.

| Posizione lista | Indice software | Etichetta / parametro software |
|---:|---:|---|
| 0 | `0xFFFFFFFF` | Exit: non chiama il setter |
| 1 | 0 | Auto / 0 |
| 2 | 1 | ISO 50 |
| 3 | 2 | ISO 64 |
| 4 | 3 | ISO 80 |
| 5 | 4 | ISO 100 |
| 6 | 5 | ISO 120 |
| 7 | 6 | ISO 125 |
| 8 | 7 | ISO 140 |
| 9 | 8 | ISO 160 |
| 10 | 9 | ISO 200 |
| 11 | 10 | ISO 250 |
| 12 | 11 | ISO 280 |
| 13 | 12 | ISO 320 |
| 14 | 13 | ISO 400 |
| 15 | 14 | ISO 500 |
| 16 | 15 | ISO 640 |
| 17 | 16 | ISO 800 |
| 18 | 17 | ISO 1000 |
| 19 | 18 | ISO 1250 |
| 20 | 19 | ISO 1600 |
| 21 | 20 | ISO 2000 |
| 22 | 21 | ISO 2500 |
| 23 | 22 | ISO 3200 |

Il convertitore originale accetta anche indice **23 → 6400**, verificato separatamente in [25 casi CPU](S33_GUI_Debug_Valori_ISO_Tempo_CPU_20261027.md), ma questa lista non ha una voce per l'indice 23. La prova della lista completa non ha iniettato una voce 6400. Per indice 24 il convertitore scrive zero nel test separato; non va interpretato come una nuova sensibilità ISO. `Exit` conserva i valori iniziali, mentre `Auto` corrisponde a indice/parametro software zero; il comportamento dell'AE resta da verificare.

Il percorso provato usa il controllo classe 9 in RAM sintetica, flag di inoltro attivo, evento logico 0x580 generato dallo scanner e inoltro originale diretto 0x4801 al genitore ISO; getter e setter ISO originali scrivono RAM emulata. I servizi di enumerazione, selezione iniziale, focus, aggiornamento, lock, segnale e consegna 0x4409 sono fixture; la richiesta di ritorno è bloccata da count finestra sintetico zero. [Analisi del controllo e prova con flag negativo](S33_GUI_Scanner_Conferma_Controllo_ISO_CPU_20261104.md); [lista e stringhe originali](S33_GUI_Debug_ISO_Lista_e_Conferma_CPU_20261027.md).

Non è dimostrato che la lista sia raggiungibile su fotocamera, che il sensore applichi tutti i valori, che l'AE non li sovrascriva, che il valore persista o che non esistano altri percorsi ISO nel firmware. Nessun test hardware/SD; **NON_INSTALLARE**.
