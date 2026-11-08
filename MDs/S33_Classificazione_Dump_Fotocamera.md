# Dump della S33: classificazione verificata

**Continuazione:** aggiunti [ClockSettings ePerfLog](S33_ClockSettings_PerfLog_e_Avvio_Osservato.md), confermati dall’utente dallo stesso avvio. Sono2file esterni archiviati separatamente: la classificazione dei14fileDUMPS sotto resta distinta.

20 ottobre 2026 — R0/R3/R4. La cartella indicata come `/DUMPS` è stata trovata in realtà nella radice del progetto: `DUMPS/`. Analizzati **14 file, 84,307,070 byte complessivi**. Gli originali restano lì, senza modifiche. La somma comprende file sovrapposti e duplicati: non misura capacità fisica o quantità unica di memoria salvata.

[Cartelle per categoria](../Risultati/Dump_fotocamera/Categorie/), [catalogo CSV](../Risultati/Dump_fotocamera/20261020T134041Z/catalogo.csv), [evidenze/hash/controlli](../Risultati/Dump_fotocamera/20261020T134041Z/verified_evidence.json). Le cartelle per categoria contengono **collegamenti agli originali**, non copie indipendenti di backup. Script: [s33_classify_camera_dumps.py](../Python_Trace_Scripts/s33_classify_camera_dumps.py).

## Che cosa contiene ogni file

| File | Dimensione | Categoria | Identificazione e limite |
|---|---:|---|---|
| [BFNSetting.txt](../DUMPS/BFNSetting.txt) | 2 KiB | Configurazione DDR/clock/partizioni | Impostazioni BFN per DDR e clock/PLL, comprese DDR_SIZE_ID=0120 e versioni. ID e divisori non sono capacità o frequenze già decodificate. |
| [BootCode.dmp](../DUMPS/BootCode.dmp) | 384 KiB | Avvio | TBIB originale completo, header e somma validi; coda FF. Non include da solo il boot NAND iniziale. |
| [BootNANDBase.dmp](../DUMPS/BootNANDBase.dmp) | 8 KiB | Avvio | Base di avvio NAND, distinta da TBIB; 8192byte ricostruiti dalle prime sottounità del NANDP1. |
| [Calibration.dmp](../DUMPS/Calibration.dmp) | 512 KiB | Calibrazioni | Archivio InfoMgr:16record con ID/dimensione corrispondenti a CalibrationItem.txt. Significato dei valori non decodificato. |
| [CalibrationItem.txt](../DUMPS/CalibrationItem.txt) | 296 B | Calibrazioni | Indice testuale dei16record di calibrazione; coincide con il binario. |
| [Calibration_2.dmp](../DUMPS/Calibration_2.dmp) | 512 KiB | Calibrazioni | Duplicato esatto di Calibration.dmp; il nome non prova una seconda banca fisica. |
| [CameraParam.dmp](../DUMPS/CameraParam.dmp) | 128 KiB | Parametri fotocamera | Area persistente parametri con header InfoMgr ID e nomi ADC/KEY_SCAN/StereoCali/EFA; schema interno non interamente decodificato. |
| [CameraParam_2.dmp](../DUMPS/CameraParam_2.dmp) | 128 KiB | Parametri fotocamera | Duplicato esatto di CameraParam.dmp; origine fisica della copia non dimostrata. |
| [MainCode.dmp](../DUMPS/MainCode.dmp) | 18816 KiB | Programma principale | Contenitore TBM/RHIR installato: identico al candidato SD; coda FF di capacità partizione. |
| [NANDP1.dmp](../DUMPS/NANDP1.dmp) | 42768 KiB | Esportazione NAND | Esportazione NANDP1 con20736record da2112byte; lettore incrementa il buffer di2112. Dati aggiuntivi e rimappatura/ECC non decodificati. |
| [NANDPartition.txt](../DUMPS/NANDPartition.txt) | 561 B | Configurazione DDR/clock/partizioni | Dimensioni dichiarate di5aree, coerenti con i dump in unità16KiB; ProductID6113 e partition version1009. Non è una mappa RAM. |
| [NANDReserved.dmp](../DUMPS/NANDReserved.dmp) | 19072 KiB | Risorse e area riservata | Area riservata con metadati e P1RES originale completo a offset512; contiene risorse software, non soltanto byte liberi. |
| [NIKON001.DSC](../DUMPS/NIKON001.DSC) | 512 B | Segnaposto | 512spazi ASCII e nessun altro contenuto; non è un JPEG o un dump di stato informativo. Scopo non dimostrato. |
| [ReservedItem.txt](../DUMPS/ReservedItem.txt) | 198 B | Risorse e area riservata | Indice di3item ripetuti due volte: header512, area18MiB, item finale512; start in settori512 coerenti. |

Le categorie sono basate su header, confronti integrali, strutture e collegamenti al codice Nikon già ricostruito. Un’estensione `.dmp` da sola non significa RAM: **nessuno dei file esaminati è stato identificato come una cattura della RAM runtime**.

## Riscontro principale: il programma modificato è nel dump fornito

I primi **17.615.360 byte (`0x10CCA00`) di MainCode.dmp** coincidono integralmente con il TBM del candidato SD locale. La successiva coda di1.652.224byte è tutta `FF`, fino alla dimensione esportata di19.267.584byte. Corrispondono tutti e16i payload;15sono identici anche all’originale, mentre il payload0 contiene esattamente la variante SD. Le16somme dei record e somma/complementoKHIR sono coerenti.

Questo è più forte della sola conferma del nome del BIN: **il file MainCode consegnato contiene i byte del candidato**. Il metodo con cui la fotocamera ha acquisito il dump resta riferito dall’utente e collegato staticamente ai comandi C1–C11 del NANDTool; l’agente non ha riletto direttamente la flash.

Il contenitore originale completo comprende anche header esterni, TBIB, P1RES e trailer. MainCode.dmp non è quell’intero contenitore e non va rinominato firmware.bin per ricavarne un aggiornamento.

## Avvio: due oggetti distinti

**BootCode.dmp:** primi294.912byte (`0x48000`) uguali al TBIB originale, con header base/entry`0x01000000`, corpo`0x44BBC` e somma interna verificata. La coda di98.304byte è tuttaFF. Quindi il contenuto TBIB esportato non è stato alterato dal candidatoSD. Questo non dimostra che l’updater abbia evitato di riscriverlo durante l’installazione.

**BootNANDBase.dmp:**8.192byte, diversi dal TBIB. Una ricostruzione limitata prende512byte ogni528 dalle prime16sottounità del NANDP1 e ottiene esattamente questo file. È una relazione di byte osservata, non un formato da applicare indiscriminatamente al resto del NAND. Il ruolo di base d’avvio è sostenuto anche dal comando NANDToolC6 già ricostruito. Esecuzione al reset e possibilità di recupero restano da chiudere.

## Calibrazioni e parametri

Calibration.dmp eCalibration_2.dmp sono identici byte per byte e SHA-256. Anche CameraParam.dmp eCameraParam_2.dmp sono identici. Il nome `_2` non basta a dimostrare da quale banca fisica sia stata letta la seconda esportazione; non contare le coppie come contenuti diversi.

Entrambe le famiglie iniziano con `InfoMgr ID`. In Calibration il conteggio a`0x68` vale16. Dal primo record a`0x6C` si leggono ID, lunghezza e dati, allineando il record successivo a4byte: tutti gli ID e le dimensioni coincidono con CalibrationItem.txt. La catena termina a`0x3294C`; il resto dell’area non è dichiarato libero. Il contenuto semantico dei singoli valori non è ancora decodificato.

| ID calibrazione | Byte dati | Offset record nel dump |
|---|---:|---|
| 22 | 8 | `0x6c` |
| 54 | 6 | `0x7c` |
| 23 | 256 | `0x8c` |
| 1 | 256 | `0x194` |
| 2 | 256 | `0x29c` |
| 9 | 692 | `0x3a4` |
| 40 | 1080 | `0x660` |
| 8 | 8012 | `0xaa0` |
| 21 | 102400 | `0x29f4` |
| 27 | 5 | `0x1b9fc` |
| 60 | 8 | `0x1ba0c` |
| 7 | 92012 | `0x1ba1c` |
| 46 | 648 | `0x32190` |
| 47 | 648 | `0x32420` |
| 63 | 648 | `0x326b0` |
| 41 | 1 | `0x32940` |

CameraParam contiene anche nomi comeADC,KEY_SCAN,StereoCali,EFA. Questo non basta ad assegnare un significato a ogni campo o a usarlo come struttura RAM caricabile. Sono dati della macchina da conservare; il firmware originale scaricato non è automaticamente un sostituto delle sue calibrazioni.

## Risorse: NANDReserved non significa spazio vuoto

A offset **512** di NANDReserved.dmp si trovano tutti gli **11.691.542byte del P1RES originale**, identici byte per byte. L’header iniziale contiene magic `59 44 33 AA` e tag `ARMI`, `ERMI`, `BRMI`, registrati senza attribuire loro semantica non dimostrata.

ReservedItem.txt contiene3righe ripetute due volte. Con start interpretato in settori512byte, gli intervalli rientrano nel dump: itemID0 aoffset0/lunghezza512; ID4 aoffset512/lunghezza18.874.368; ID1 aoffset18.874.880/lunghezza512. Il P1RES noto rientra interamente nell’item4. La ripetizione testuale non dimostra due copie fisiche complete e l’areaReserved non è RAM o flash libera.

## NANDP1: record raw, non immagine logica pronta da ripristinare

**Aggiornamento:** la proiezione storica descritta sotto è superata dalla [ricostruzione logica completa dei sette export](S33_NAND_Mappa_Logica_e_Ricostruzione_Integrale_Export.md). ECC e ripristino fisico restano aperti.

Il file misura43.794.432byte: **20.736record da2.112byte (`0x840`)**. La funzione Nikon`0x1ED37C`, chiamata dal dumpC9, avanza il puntatore di`264 << 3 = 2112` a`0x1ED41A`. Questo conferma lo stride oltre alla sola divisibilità della dimensione.

Una proiezione provvisoria che trattiene i primi2048byte di ogni record contiene integralmente BootCode aoffset`0x20000`, CameraParam a`0x140000` eCalibration a`0x180000`. Il MainCode noto a`0x1240000` coincide per`0x6C0000`byte, poi diverge; NANDReserved a`0x23A0000` coincide per`0x4C0000`byte, poi diverge. **La proiezione non ricostruisce quindi l’intera immagine logica.** I64byte aggiuntivi sono compatibili con informazioni spare/OOB, ma ECC, marcatori e rimappatura dei blocchi non sono decodificati. Anche la base iniziale usa il diverso raggruppamento osservato sopra.

Non concatenare questi dump e non usare NANDP1 come ripristino grezzo senza ricostruire mappa e formato. Non è dimostrato che copra tutto il chip, tutte le partizioni o tutte le copie necessarie al recupero. La dimensione raw o i40,5MiB della proiezione non indicano capacitàRAM o capacità totale della NAND.

## Configurazione: utile per RAM e caricamento, ma da decodificare

NANDPartition.txt espone dimensioni che, moltiplicate per **16KiB**, corrispondono esattamente a tutti e5i rispettivi dump: BootCode,Calibration,CameraPara,Reserved,HexMain. È un’unità derivata dalla coerenza fra metadati e file, non una misura già provata della dimensione fisica di eraseblock. ProductID`0x6113` coincide con la pagina FW VERSION fotografata; Partition_Ver è`0x1009`.

BFNSetting.txt registra impostazioniDDR ePLL/clock, fra cui `DDR_SIZE_ID_Variable_09 = 0x00000120`, DDR_Off0x18=`0x4DE`, DDR_Off0x20=`0x584`, Clock_DDR2_Control=`0x2080`, BFN_Setting_Version=`0x10001` eSystem_FormatVersion=`0x10000`. **0x120 è un identificatore da decodificare: non significa automaticamente288MB,128MB o altro.** I divisori non danno frequenze senza ricostruire il circuito e la sorgente clock. Questo file è una pista concreta per le questioniRAM ancora aperte.

## File segnaposto

NIKON001.DSC contiene soltanto512spaziASCII (`0x20`), senza header fotografico o altri dati. È classificato come segnaposto dal contenuto; lo scopo preciso resta ignoto. L’estensioneDSC non lo rende un’immagineJPEG.

## Riproduzione, controlli e prossima verifica

```bash
python3 Python_Trace_Scripts/s33_classify_camera_dumps.py
```

Verificati14hash e preservazione integrale degli input,2coppie duplicate,16payload/sommeTBM,KHIR,TBIB/somma interna,P1RES completo,16record calibrazione/allineamenti,5dimensioni di partizione e relazioni limitate NAND. Tre finestreGNU nuove sono nel [riscontro](../Risultati/Dump_fotocamera/20261020T134041Z/gnu_verified.txt). Il classificatore lascia anche uno snapshot del sorgente e controlla i collegamenti delle categorie.

La scansione firme REA/Binwalk non era disponibile perché manca la configurazione del comando esterno; [tentativo conservato](../Risultati/Dump_fotocamera/rea_scan_attempt.json). Non è stato installato o configurato alcuno strumento. Le conclusioni qui dipendono dai confronti e dai parser locali, non da una scansione che non è avvenuta.

Prossimo punto utile: correlare DDR_SIZE_ID e impostazioniBFN al codice di inizializzazione; perR4, ricostruire la corrispondenza fisico/logico del NAND e il reset. **Avere questi file migliora l’evidenza sui byte e conserva parametri importanti, ma non dimostra un ripristino eseguibile.** Nessuna operazione sulla fotocamera, nessuna modifica ai dump o alle cartelleGNU; circa10% funzionaleAkeruOS invariato.

## Continuazione BFN/NAND verificata — 20 ottobre 2026

[Nuovo raccordo](S33_BFN_NAND_DDR_e_Configurazione_Persistente.md):28campi BFN coincidono con quattro record NANDP1 identici; testo ricostruito byte per byte,9coppie DDR eIDseparato. È configurazione persistente, distinta dalla tabellaCSV dei clock. CapacitàRAM, frequenze effettive e indipendenza fisica delle copie restano aperte. Prossimo: consumatoreDDR_SIZE_ID nel primo stadio.

## Continuazione: dimensione configurata decodificata — 20 ottobre 2026

Il [consumatore nel BootNAND](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md) ora chiarisce il significato software dell’ID: byte basso ×8 MiB, quindi256 MiB configurati per0120; bit8 distinto nel controller. Verificati12casi aritmeticiCPU e2checksum originali. Questo supera «ID ancora non decodificato», senza certificare RAM fisica o una banca contigua utilizzabile. Checksum BFN5A97D e test RAM sparso ricostruiti; profilo128MiB del laboratorio non modificato. Prossimo: loader e dati NAND successivi ai primi512byte.

## Continuazione: P1IDSTR e handoff TBIB — 20 ottobre 2026

Il [nuovo rapporto loader](S33_NAND_P1IDSTR_Blocchi_Boot_e_Handoff_TBIB.md) identifica24copie identiche della tabella244byte, raccorda tutti i393216byte BootCode ai blocchi1/2/3 e verifica inCPU originale checksum e salto alTBIB da un contesto post-trasferimento dichiarato. Il TBIB raggiunge la prima scrittura stack non fornita nel laboratorio; non è boot completo né prova del controllerNAND. Prossimo: campi partizioni/managerNAND e divergenze delle proiezioni MainCode/Reserved.

## Continuazione: ricostruzione logica completa — 20 ottobre 2026

La [mappa logica dai metadati NAND](S33_NAND_Mappa_Logica_e_Ricostruzione_Integrale_Export.md) supera il limite delle proiezioni parziali: tutti i7export sono ricostruiti byte per byte,40.501.248byte totali.295IDunivoci negli spare e16slot finali FF secondo il lettore verificato;304casi CPU. La semplice concatenazione fisica resta una proiezione errata per MainCode/Reserved. Non è una certificazione di ECC, chip intero o recupero. P3nel testo non viene aggiornato dal getter. Prossimo: esiti lettura raw/P3 e loaderTBM/risorse.

## Continuazione: ECC e status raw — 20 ottobre 2026

Il [nuovo controllo ECC](S33_NAND_ECC_Integrita_e_Limite_Errori_Export_Raw.md) copre tutti i165.888settori del file:151.040nei gruppi mappati sono tutti coerenti;128differenze restano nei record azzerati di quattro gruppi non mappati.2.105casi CPU del correttore passati. Il ritorno di ogni lettura raw non viene propagato dall’exporter:12prove al confine del ritorno e riscontro statico, non simulazione completa. Fonti primarie Linux archiviate; nessun dump corretto o hardware modificato. Prossimo: loaderTBM/risorse e residenza.
