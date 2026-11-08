# ClockSettings e PerfLog: campi software e avvio registrato dalla S33

20 ottobre 2026 — R0/R1/R3/R4. L’utente ha confermato che i due file provengono **dallo stesso avvio** dei14file DUMPS. Analisi locale, senza contatti con la macchina. Gli originali esterni non sono stati modificati; copie esatte e hash sono conservati nei [risultati](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/).

Risultato:12stati clock,180valori tutti zero;37eventi PerfLog tutti raccordati a ID/etichette del firmware fornito;13intervalli appaiati. I due avvisi iniziali derivano da etichette boot mancanti nell’esportatore. Nessuna nuova capacitàRAM, frequenza fisica, fotografia AkeruOS o garanzia di recupero dedotta. Il circa10% funzionale resta invariato; la GUI HiddenMenu osservata sull’hardware è già documentata nel [rapporto fotografico](S33_HiddenMenu_Hardware_Foto_e_Versioni.md).

## File e prove

- [ClockSettings originale preservato](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/fonti/ClockSettings.csv):802byte,12righe dati,15campi per stato, terminatoreNUL finale incluso.
- [PerfLog originale preservato](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/fonti/PerfLog.txt):2744byte,37righe evento,2avvisi e1separatore.
- [Evidenze/hash](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/verified_evidence.json), [13finestre GNU](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/gnu_verified.txt), [eventi](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/perf_events.json), [intervalli](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/perf_phases.json), [180campi con indirizzi software](../Risultati/Dump_fotocamera/Clock_Perf/20261020T152232Z/clock_fields.json).
- [Script riproducibile](../Python_Trace_Scripts/s33_analyze_clock_perf_exports.py). Il classificatore generale dei14dump resta [separato](S33_Classificazione_Dump_Fotocamera.md).

Sono stati ricontrollati i14hash dei DUMPS contro la classificazione precedente, il firmware originale e i16payload tramite gli helper esistenti. Tutte le finestre di codice, i pool e le etichette usate qui coincidono anche con i byte di MainCode.dmp, che contiene il candidato installato. Non viene trasferito automaticamente alla macchina attuale un indirizzo dei vecchi logV1.0. Gli strumenti GNU sono usati soltanto in lettura; hash di objcopy/objdump invariati prima/dopo, ELF intermedi in directory temporanee.

## ClockSettings.csv non misura le frequenze effettive

Il file ha intestazione16colonne: StateID più15nomi di dominio, fra cui Base-ARC, DSP-ARC, DRAM, Capture eSensor. Le righe OpState[0]..OpState[11] contengono tutte15zeri:180campi numerici. **Non equivale a CPU eDRAM ferme a0Hz**, né fornisce frequenzeMHz da inserire nell’emulatore.

Il codice di esportazione verificato è C6760..C683E. Chiede al getter14CBDC la riga0, poi avanza su12record con stride156byte; il getter calcola base443FF0+156×indice. Il formatterC6900 legge15word della struttura, non registri hardware del clock.

| Colonna | Offset nella riga software |
|---|---:|
| Base-ARC |28|
| DSP-ARC |36|
| DRAM |44|
| DispScalar |52|
| DispEngine |60|
| Capture |68|
| Sensor |76|
| ARB |84|
| DispTG |92|
| Audio |100|
| CMOS |116|
| Line |124|
| IRP |132|
| NRE |140|
| HDVD-SSI |148|

La tabella candidata occupa443FF0..444740, ma il CSV espone solo queste180word, non tutti i byte dell’intervallo. È informazione sparsa su campi software al momento dell’esportazione, **non un dumpRAM completo o una prova che l’area sia libera**. Non è ancora ricostruito perché i campi siano zero: possono mancare configurazioni della tabella o essere valori convenzionali; non attribuire uno stato fisico ai singoli domini senza seguire gli scrittori e i consumatori.

Il byteNUL finale è coerente con il writer: dopo la differenza fra puntatore finale e iniziale, aC680C aggiunge1 alla lunghezza da scrivere. Il parser lo conserva nella copia originale e lo esclude soltanto dalla vistaCSV, senza trattarlo come un tredicesimo stato. Non ci sono NUL interni.

## PerfLog:37etichette tutte riconosciute

La tabella boot a370A74 contiene6puntatori:4etichette valide (BOOT_STARTUP, MAINCODE_LOAD_START/END, BOOT_END) e2nulli. Il getterBCFFC accetta indici0..5; l’esportatore1F1138 li attraversa tutti e scrive l’avviso quando il puntatore è nullo. Nel file ci sono esattamente4eventi boot e2avvisi corrispondenti. **Quegli avvisi non dimostrano due guasti durante l’avvio**: si spiega la loro produzione nel codice di esportazione.

Gli altri33eventi usano le etichette principali B00000..B0000D della tabella38EE24 oppure le etichette B80000..B80048. La tabella aggiuntiva370950 viene registrata daBCFF0→12CA94 con73voci; il registrar scrive puntatore e conteggio nel gestore3668B4. Tutte le37etichette del file corrispondono alla stringa puntata dall’indice previsto. Le due occorrenze di SetDisplayPath e gli eventi con lo stesso timestamp restano distinti, con il loro numero di riga.

## Timestamp: formato compreso, scala del campione da chiudere

Nel writer generale1F10C8, la word+4 del record è la parte bassa e la word+8 la parte alta. L’helper335C4C con shift32 ricava la parte alta, poi il formatter stampa **high32,low32** con due conversioni decimali. In questo file tutti i primi campi sono zero e i secondi restano positivi. Non sono due tempi da sommare.

Per i4eventi boot il writer1F1138 forza esplicitamente a0 il primo argomento temporale e prende il secondo da900+3C+8×indice. Il fatto che il campoalto stampato sia0 non basta quindi a provare che un timestamp boot64bit fosse stato letto integralmente.

La conversione Main12CBA4 usa il fattore1.000.000 e due percorsi selezionati dal byte3668BC: un percorso dipende da parametri runtime/frequenza; l’altro moltiplica una differenza64bit e divide per32768 tramite shift15. È una normalizzazione software significativa, ma il valore runtime del selettore e i parametri effettivi non sono in questi file. **Gli intervalli sotto restano in unità stampate**: nessuna frequenza fisica o durata insecondi viene certificata con questi soli dati. Boot eMain hanno basi separate; Maincode start è0, quindi non si sottrae un timestampMain da unoBoot per ottenere un tempo totale.

## Sequenza utile per AkeruOS

| Marcatore Main | Valore stampato |
|---|---:|
| Maincode start |0|
| Load Calibration Start |47424|
| Turn On Senor Start (nome del firmware) |47821|
| Load Calibration End |87615|
| Turn On Senor End |112518|
| Enter Liveview |321990|
| P1 mount ready |511016|
| Mount start |516693|
| Mount end |1005859|
| Load C4 End |1347167|

Gli intervalli Calibrazione eSensore si sovrappongono nel registro degli eventi. Il marcatore EnterLiveview compare prima di Mountstart/end. Per AkeruOS questo aiuta a separare preparazione dell’inquadratura e disponibilità del percorso di salvataggio, senza confondere il completamento dei due servizi. **L’ordine di questo avvio non prova causalità, esecuzione su core diversi, primo frame effettivamente mostrato o persistenzaSD.** Anche P1mountready eMountend sono marcatori distinti.

Fra gli intervalli appaiati: caricamentoMain boot246963; calibrazione40191; sensore64697; caricamentoC2=145416,C3=169250,risorse208038,C4=144378; Mount489166,sempre in unità stampate. Le sigleC2/C3/C4 non sono state identificate con indiciTBM o overlay11–15: il collegamento a file/residenza richiede i chiamanti dei marcatori e i loader.

Dopo la prima sequenza, a8571624 compare un’altra preparazioneDisplayPath, con Recorder_DisableLVW1ISR Start/End al suo interno, e fine a8650085. Non è un secondo boot e non dimostra da solo una foto o una commutazione di modalità specifica.

## Riproduzione e prossimo passo

```bash
python3 Python_Trace_Scripts/s33_analyze_clock_perf_exports.py
```

Per ripetere la verifica se gli originali in Documenti non fossero più presenti, usare `--clock` e `--perf` con le copie in fonti della cartella risultati. Ogni run crea una nuova directory e verifica gli input prima/dopo, senza-O. Il controllo corrente ha esito PASS_EXPORT_STRUCTURE_AND_FIRMWARE_CORRELATION:12stati,180campi,37etichette,13intervalli,13finestreGNU,16pool e14hashDUMPS ricontrollati.

**Prossimo per il goal AkeruOS:** collegare configurazioneBFN/DDR eDDR_SIZE_ID0120 al boot e ai suoi registri; perPerf, chiudere la scala runtime e collegareC2/C3/C4 ai loader. PerNAND restanoECC/rimappatura e copertura fisica/logica; per i parametri/calibrazioni rimane da interpretare il contenuto dei record. I nuovi file aiutano a studiare la macchina realmente avviata, ma non trasformano i dump in un ripristino completo e non completano ancora l’applicazione fotografica.

## Continuazione BFN/NAND verificata — 20 ottobre 2026

[Nuovo raccordo](S33_BFN_NAND_DDR_e_Configurazione_Persistente.md):28campi BFN coincidono con quattro record NANDP1 identici; testo ricostruito byte per byte,9coppie DDR eIDseparato. È configurazione persistente, distinta dalla tabellaCSV dei clock. CapacitàRAM, frequenze effettive e indipendenza fisica delle copie restano aperte. Prossimo: consumatoreDDR_SIZE_ID nel primo stadio.

## Continuazione: dimensione configurata decodificata — 20 ottobre 2026

Il [consumatore nel BootNAND](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md) ora chiarisce il significato software dell’ID: byte basso ×8 MiB, quindi256 MiB configurati per0120; bit8 distinto nel controller. Verificati12casi aritmeticiCPU e2checksum originali. Questo supera «ID ancora non decodificato», senza certificare RAM fisica o una banca contigua utilizzabile. Checksum BFN5A97D e test RAM sparso ricostruiti; profilo128MiB del laboratorio non modificato. Prossimo: loader e dati NAND successivi ai primi512byte.

## Continuazione caricamenti — 20 ottobre 2026

Il [raccordo ai loader](S33_Gruppi_C2_C3_C4_Risorse_e_Segnali_Caricamento.md) identifica ora C2=TBM2/3, C3=4/5, C4=6/7 e Resource=TBM9, distinto dal P1RES. Superata la precedente questione sull’identità dei gruppi. 48 prove condizionali con sei servizi simulati verificano i segnali intermedi di C3/C4 e l’assenza di controllo degli esiti evento/rilascio prima di End. Non eseguono trasferimenti o sincronizzazione. Scala temporale e modalità runtime928 restano aperte; prossimo: consumatori dei bit e ownership.

## Continuazione — significato del segnale finale

[Load Later e i suoi consumatori](S33_Load_Later_Attese_Bit_Persistenti_e_Limite_Ready.md) precisano ora il contratto: bit08 consumato prima della seconda letturaC3; bit80 finale richiesto anche dopo letture fallite nei test condizionali. Resource fallito e successo danno entrambiFC. End e bit80 non certificano dunque isolatamente tutti i trasferimenti. Queste sono proveCPU con I/O simulato, non errori osservati nell’avvio del PerfLog. Scala temporale runtime ancora aperta.
