# CaptureMenu: richieste tempo e impostazioni — CPU emulata

Il 5 novembre 2026 il [banco CaptureMenu con focus originale](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py) è stato esteso per confrontare un valore di configurazione `0xCAD30=0x2C` imposto dalla fixture con il precedente valore sintetico `0x46`. `0x2C` coincide con il valore statico individuato nel campione TBIB V1.1, ma il banco non legge il valore runtime della fotocamera. Restano imposti `0xCA310=0`, stato iniziale, MMIO, guardie e consegna degli eventi.

Il percorso usa snapshot sintetico → scanner e coda originali → dispatcher → AutoScene → manager → CaptureMenu originale ID 2, selezione e focus originali della risorsa `0x4801`, aggiornamento dei record originali e successiva pressione logica. Il secondo evento viene generato e consegnato dal banco: non è identificato con un pulsante fisico.

Con il flag iniziale bit 1 impostato dal banco, il controllo attivo selezionato è `0x980268`. In configurazione sintetica `0x2C`, i quattro flag dopo l'aggiornamento sono `08,00,00,00`; con `0x46` sono `08,00,02,02`. Pertanto, nelle condizioni provate, i due ultimi record non vengono bloccati con `0x2C`; ciò **non** dimostra che lo siano o meno sulla camera.

## Destinazioni di prova

Nella sola RAM della copia di laboratorio, la variante `--custom-targets` cambia i campi destinazione degli ultimi due record da `0x0A` e `0xBB` a `0x3E` e `0xB7`, e imposta a 1 l'argomento del secondo. `0x3E/0` è la richiesta usata nel [banco della schermata diagnostica tempo](S33_GUI_Menu_Scanner_Tempo_Sequenza_CPU_20261104.md); `0xB7/1` è la richiesta usata nel [banco impostazioni](S33_GUI_Impostazioni_Apertura_Occupato_CPU_20261104.md). Sono destinazioni di prova, non l'assegnazione definitiva dei quattro tasti richiesti.

| Pressione logica successiva | Record originale | Record modificato nella prova |
|---|---|---|
| `0x2180` | richiesta intercettata `0x0A, 0` | richiesta intercettata `0x3E, 0` |
| `0x2700` | richiesta intercettata `0xBB, 0` | richiesta intercettata `0xB7, 1` |

Le richieste successive sono intercettate ai siti `0x631B08` e `0x631BE4` nella copia di laboratorio: il manager **non** apre le destinazioni in questa prova. Il banco verifica i parametri effettivamente passati, la selezione/focus, i flag, lo stack e il contenuto completo dei quattro record dopo l'ultimo caso; le modifiche ammesse sono i tre campi indicati e il seed dei flag. Con guardia manager iniziale attiva, la prima apertura resta bloccata e il secondo evento non viene consegnato.

**4/4 casi PASS** per ciascuna delle due varianti indipendenti della fixture UI `0` e `0x23`: [UI 0](../Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T104720469790Z/verified_evidence.json), [UI 0x23](../Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T104721281046Z/verified_evidence.json). Confronti: [record originali e `0x2C`](../Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T104722134034Z/verified_evidence.json) e [record originali e `0x46`](../Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T104723010244Z/verified_evidence.json), 4/4 ciascuno. Ogni gruppo comprende due pressioni successive e due casi con guardia iniziale attiva.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py --boot-2c --custom-targets`, con `--ui-mode-23` per l'altra fixture; omettere `--custom-targets` per i record originali, o entrambe le opzioni per il caso storico `0x46`. I primi tentativi di lasciare aperte le destinazioni originali sono conservati come FAIL perché richiedevano ulteriore stato di dispositivo non modellato; l'intercettazione serve a misurare le richieste, non dimostra apertura o rendering.

REA è stato consultato per aprire un ELF ARC700 locale, ma ha restituito `unsupported ELF architecture`; la prova usa gli strumenti ARC/GNU e il modello DSP sperimentale già disponibili. Nessuna modifica all'emulatore è stata necessaria o validata in questa prova.

Non sono dimostrati tasti fisici, ordine visivo, testo o icone corretti, navigazione dei menu richiesti, lifecycle completo, concorrenza, unità del tempo o effetto sul sensore. Il menu a quattro tasti desiderato e la selezione colore/mono restano da integrare. Le variazioni esistono solo nelle copie fixture e non sono una patch installabile. **NON_INSTALLARE**.
