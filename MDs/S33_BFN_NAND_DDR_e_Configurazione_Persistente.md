# BFN: configurazione NAND, descrittori DDR e testo esportato

20 ottobre 2026 — R0/R3/R4. Analisi locale dei dump forniti dall’utente, con GNU ARC700 in sola lettura. Il collegamento verificato è **NANDP1 → lettore BFN → descrittore → vista esportata → BFNSetting.txt**. Non è una nuova esecuzione del boot sulla fotocamera.

## Risultato

Tutti i **28 campi** di `DUMPS/BFNSetting.txt` coincidono con word little endian in quattro record identici di `DUMPS/NANDP1.dmp`. Ricostruiti anche spazi, intestazioni e terminatori CRLF: il testo ottenuto coincide con tutti i1631byte dell’originale. Si tratta di configurazione persistente esportata, non di una lettura dei clock fisici al momento dell’export.

Il lettore costruisce nove coppie indirizzo/valore per i registri DDR. Il decimo campo, `DDR_SIZE_ID=0x120`, è separato da queste coppie: **la sua codifica non è ancora una capacità RAM decodificata**. Nessuna nuova RAM libera o frequenza viene attribuita ad AkeruOS.

## Prove e riproduzione

- [Script](../Python_Trace_Scripts/s33_trace_bfn_nand_configuration.py).
- [Indice dell’ultima verifica](../Risultati/Dump_fotocamera/BFN_NAND/latest.json).
- [Evidenze](../Risultati/Dump_fotocamera/BFN_NAND/20261020T153034Z/verified_evidence.json), [mappa dei28campi](../Risultati/Dump_fotocamera/BFN_NAND/20261020T153034Z/field_mapping.json), [quattro finestre GNU](../Risultati/Dump_fotocamera/BFN_NAND/20261020T153034Z/gnu_verified.txt).
- [Primi512byte della configurazione](../Risultati/Dump_fotocamera/BFN_NAND/20261020T153034Z/configuration_first_512.bin), [testo originale preservato](../Risultati/Dump_fotocamera/BFN_NAND/20261020T153034Z/BFNSetting.original.txt), snapshot dello script nella stessa cartella.

Comando effettivamente eseguito dalla radice:

```bash
python3 Python_Trace_Scripts/s33_trace_bfn_nand_configuration.py
```

Esito: `PASS_BFN_NAND_EXPORT_STATIC_CORRELATION`. Ricontrollati i14hash DUMPS rispetto alla [classificazione](S33_Classificazione_Dump_Fotocamera.md), il firmware originale V1.1 di29.602.084byte/SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39` e i16payload tramite helper esistente. Le quattro finestre, i pool e le stringhe utilizzate coincidono anche con i byte del MainCode fornito, comprendente la modifica HiddenMenu. Hash objcopy/objdump invariati prima/dopo; ELF temporanei fuori dagli alberi GNU. Gli originali restano intatti.

La prima esecuzione ha evidenziato un errore del parser dello script: la parola `add2` veniva letta come un ulteriore gruppo di byte esadecimali. Il parser ora separa le colonne GNU tramite tabulazioni. È un errore dello strumento di analisi corretto prima del PASS, non un errore del firmware. Le directory intermedie precedenti sono conservate; fa fede l’indice `latest.json`.

## Dove sono i dati nel dump

Gli offset seguenti sono **posizioni nel file**, non indirizzi CPU o una geometria fisica NAND certificata.

| Indice a stride2112 | Inizio record | Primo valore DDR | Primo valore clock |
|---:|---:|---:|---:|
|4|`0x2100`|`0x21A0`|`0x2280`|
|5|`0x2940`|`0x29E0`|`0x2AC0`|
|6|`0x3180`|`0x3220`|`0x3300`|
|7|`0x39C0`|`0x3A60`|`0x3B40`|

La ricerca nell’intero NANDP1 trova esattamente quattro occorrenze della sequenza DDR completa, quattro della sequenza clock completa e quattro dell’intero record2112byte. I quattro record sono identici anche nei byte ulteriori, non soltanto nei campi BFN. Il loro ruolo di ridondanza, la selezione in caso di errore e l’indipendenza fisica non sono ancora dimostrati.

Layout relativo all’inizio di ciascun record:

| Offset | Contenuto verificato |
|---:|---|
|`0xA0..0xC0`|9word di configurazione DDR|
|`0xC4`|`DDR_SIZE_ID`, valore`0x120`|
|`0x180..0x1BC`|16word di configurazione clock|
|`0x1F8`|`BFN_Setting_Version=0x10001`|
|`0x1FC`|`System_FormatVersion=0x10000`|

Il primo record parte dopo i primi8448byte raw, dai quali il classificatore ricostruisce gli8192byte BootNANDBase tramite16sottounità512/528. Questa adiacenza non prova da sola il flusso del reset né le dimensioni dei blocchi NAND.

## Il percorso nel MainCode

L’esportatore `0x300554` alloca un descrittore296byte a `fp-424`. Chiama `0x1ED440`, controlla l’errore, poi `0x301F14` con destinazione `fp-128`. Il formatter scrive i nomi dei campi e i valori con `%-40s = 0x%08x\r\n`; i nomi trovati nei pool coincidono con tutte le28chiavi del testo.

Il lettore `0x1ED440` usa il buffer candidato `0x50E140`, letto dal pool`0x1ED774`. Le word DDR sono caricate da buffer+160,+164,…,+192 e copiate negli slot valore del descrittore+4,+12,…,+68. Gli slot alternati contengono gli indirizzi dei registri, e+76 contiene il conteggio9. L’ID proviene invece da buffer+196 e viene scritto a descrittore+220 (`0xDC`).

| Chiave DDR | Valore | Indirizzo inserito nella coppia |
|---|---:|---:|
|Off0x18|`0x4DE`|`0x0FE20018`|
|Off0x20|`0x584`|`0x0FE20020`|
|Off0x80|`0x907`|`0x0FE20080`|
|Off0x84|`0xAC4B`|`0x0FE20084`|
|Off0xF4|`0x1302`|`0x0FE200F4`|
|Off0xF8|`0x9232`|`0x0FE200F8`|
|Off0x100|`0x1830`|`0x0FE20100`|
|Off0x104|`0x0`|`0x0FE20104`|
|Off0x134|`0x202`|`0x0FE20134`|

Questo prova la costruzione delle coppie da parte del software; non osserva le scritture hardware né certifica i bit dei registri. `0x50E140` è un buffer del percorso Nikon: non è memoria libera assegnabile ad AkeruOS.

Il puntatore del pool`0x1ED7A0` è `0x50E33C`, cioè buffer+`0x1FC`. I16load con offset−124,…,−64 leggono quindi buffer+`0x180..0x1BC`. Il descrittore riceve queste word a+`0xE0..0x11C`. Il sistema legge la versione formato a+`0x1FC`, la confronta con`0x10000` e nel ramo corrispondente prepara descrittore+`0x120`; la versione BFN da buffer+`0x1F8` va a+`0x124`. Lo script verifica il ramo compatibile con questo campione, non generalizza ad altri formati.

L’unpacker `0x301F14` raccoglie le nove word DDR a offset0..32 della vista, l’ID a+`0x34`, i clock a+`0x38..0x74`, SystemFormat a+`0x78` e BFNVersion a+`0x7C`. L’esportatore legge esattamente questi slot. La mappaJSON conserva per ogni chiave gli offset nelle tre rappresentazioni e il PC del load di esportazione.

## Collegamento con ClockSettings e AkeruOS

L’utente ha confermato che [ClockSettings ePerfLog](S33_ClockSettings_PerfLog_e_Avvio_Osservato.md) provengono dallo stesso avvio dei dump. BFN contiene impostazioni non nulle, mentre il CSV contiene180zeri nella tabella software`0x443FF0`. Non c’è contraddizione dimostrata: sono rappresentazioni diverse, lette da percorsi diversi. Il collegamento tra applicazione dei parametri BFN, frequenze effettive e inizializzazione della tabella CSV resta aperto.

Per R3 questo restringe la ricerca dell’inizializzazione DDR a parametri reali del campione e distingue l’ID dalle coppie di registri. Per R4 identifica dati da preservare oltre al solo TBIB/MainCode, senza dichiarare il NANDP1 un backup completo recuperabile. Circa10% funzionale invariato: nessun nuovo avvio AkeruOS o JPEG prodotto.

## Continuazione

Seguire il consumatore di `DDR_SIZE_ID` nel primo stadio BootNANDBase e nel boot Nikon, verificando base di esecuzione, maschere e calcolo prima di tradurre`0x120` in capacità. In parallelo logico, ma senza confondere le prove, rimangono selezione dei quattro record, dati dopo i primi512byte, ECC/rimappatura e ricostruzione NAND completa. Non creare RAM sintetica o modificare clock, NAND o firmware sulla base di questo solo export.

## Continuazione: dimensione configurata decodificata — 20 ottobre 2026

Il [consumatore nel BootNAND](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md) ora chiarisce il significato software dell’ID: byte basso ×8 MiB, quindi256 MiB configurati per0120; bit8 distinto nel controller. Verificati12casi aritmeticiCPU e2checksum originali. Questo supera «ID ancora non decodificato», senza certificare RAM fisica o una banca contigua utilizzabile. Checksum BFN5A97D e test RAM sparso ricostruiti; profilo128MiB del laboratorio non modificato. Prossimo: loader e dati NAND successivi ai primi512byte.

## Continuazione: P1IDSTR e handoff TBIB — 20 ottobre 2026

Il [nuovo rapporto loader](S33_NAND_P1IDSTR_Blocchi_Boot_e_Handoff_TBIB.md) identifica24copie identiche della tabella244byte, raccorda tutti i393216byte BootCode ai blocchi1/2/3 e verifica inCPU originale checksum e salto alTBIB da un contesto post-trasferimento dichiarato. Il TBIB raggiunge la prima scrittura stack non fornita nel laboratorio; non è boot completo né prova del controllerNAND. Prossimo: campi partizioni/managerNAND e divergenze delle proiezioni MainCode/Reserved.
