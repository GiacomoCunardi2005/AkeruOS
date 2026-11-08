# NAND dal PC: dump di blocchi, doppia lettura e risultati parziali

21 ottobre2026 — continuazione del client Linux. **Implementato un nuovo strumento per acquisire intervalli espliciti di blocchi**, confrontando due letture di ciascuna pagina. Nove scenari offline passati, più sei rifiuti di coordinate e tre controlliCLI. Questa modifica riguarda il softwarePC; il firmware candidato non cambia e non viene presentato come pronto da installare.

## File e prove

- [Nuovo client](../Python_Trace_Scripts/s33_nand_pc_dump.py), basato sul [lettoreSG_IO esistente](../Python_Trace_Scripts/s33_nand_pc_read.py).
- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_dump.py), [manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/pc_dump_20261021T143223Z/verified_evidence.json), [scenari](../Risultati/USB_SCSI/Accesso_NAND_PC/pc_dump_20261021T143223Z/cases.json).
- [Client precedente eABI](S33_NAND_PC_Offset_Differiti_Corretti_e_Client_Linux.md), [statoRAM corrente](S33_NAND_PC_API_Regioni_e_Configurazione_Successiva.md).

Riproduzione esclusivamente locale:

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_dump.py
python3 Python_Trace_Scripts/s33_nand_pc_dump.py --help
```

## Comportamento del nuovo client

Gli argomenti sono `--device`, `--chip` (default0), `--first-block`, `--blocks` e `--output-dir`. Non seleziona automaticamente un disco e non avvia il firmware. Occorre un'immagine compatibile già in esecuzione: questo requisito non è stato verificato sulla fotocamera per il candidato attuale. Non viene qui fornita una procedura d'installazione.

Il range deve stare nel profilo configurato: blocchi0..511 e64pagine per blocco,2112byte per pagina. Non è una misura della capacità fisica. Il chip segue il contrattoCDB esistente; il firmware deve accettarlo secondo la propria geometria runtime.

La cartella di output deve essere nuova; gli argomenti vengono validati prima di aprire il dispositivo. L'apertura usa **O_RDONLY**, sul descrittore effettivamente aperto si eseguono i controlli Nikon04b0:035d, interfaccia08/06/50 eLUN0 già presenti nel lettore. Non ci sono riaperture automatiche del dispositivo o retry silenziosi.

Per ogni pagina vengono inviate due richiesteSG_IO IN tramite lo stesso descrittore. Entrambe devono restituire2112byte con status/residuo validi; devono inoltre coincidere byte per byte. Solo allora i byte della prima lettura vengono aggiunti al file e registrati nel diario. Un errore interrompe l'intervallo senza saltare la pagina.

|File locale|Contenuto|
|---|---|
|dump.raw.partial|pagine già confrontate; mantenuto se si verifica un errore|
|pages.jsonl|coordinatechip/blocco/pagina, offset, dimensione eSHA256 di ogni pagina salvata|
|manifest.json|range richiesto, progresso, identità, stato finale o coordinata/errore|
|dump.raw|risultato concluso dopo confronto delle pagine e rilettura del file locale|

A ogni confine di blocco il programma esegueflush/fsync di dati e diario e aggiorna il manifest con sostituzione atomica locale. Al termine rilegge l'intero file, confrontaSHA256 e lunghezza, rinomina il risultato e registra `COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED`. In caso di errore nell'ultimo manifest prova a riportare il file a`.partial`. Il successo richiede manifest completo e file coerente: il solo nome del file non certifica un'acquisizione.

Non implementa la ripresa automatica: un nuovo tentativo richiede una nuova cartella. Dopo errore non cancella i dati già confrontati. Se fallisce anche la scrittura del manifest d'errore, l'ultimo manifest restaRUNNING, quindi incompleto. Un'interruzione brutale o un errore disco può lasciare una coda parziale: il diario permette di verificare le pagine complete; non viene promessa consistenza transazionale dei due file dopo perdita di alimentazione delPC.

## Cosa coprono i test

I test compilano il nucleoC `akrn_read.c` e gli inviano iCDB costruiti dal vero lettorePython, attraverso una fixture diSG_IO che ne controlla direzione, lunghezza eABI. Il nucleoC decodifica le coordinate ed esegue un backend che produce dati sintetici distinti perchip/blocco/pagina. È usata geometria di laboratorio, non letta dalla Nikon. Il kernelLinux,USB e controllerNAND non sono coinvolti.

|Scenario|Esito atteso verificato|
|---|---|
|due blocchi255→256|128pagine,256richieste, coordinate/ordine/byte/hash esatti|
|ultimo blocco511|64pagine,128richieste, nessun superamento del range|
|seconda lettura discordante|stop alla pagina3, tre pagine valide conservate|
|seconda lettura con residuo|stessa conservazione, nessun completamento|
|erroreSCSI|stessa conservazione, status rifiutato|
|erroreioctl|stessa conservazione, errore registrato|
|KeyboardInterrupt|parziale preservato, coordinata dell'interruzione registrata|
|errore manifest al confine blocco|64pagine preservate, statoFAILED|
|errore manifest finale|128pagine preservate comeparziale, statoFAILED|

Sei coordinate invalide vengono rifiutate. I tre controlliCLI verificano che una cartella esistente impedisca qualunque apertura del dispositivo, che un file regolare venga rifiutato prima diSG_IO e che l'apertura usiO_RDONLY con chiusura dello stesso descrittore. Sono confrontati anche i diari pagina per pagina e i risultati locali. Gli errori nei test sono iniezioni deliberate e attese, non guasti osservati sulla fotocamera.

## Limiti e continuazione

Due letture uguali dimostrano soltanto concordanza delle risposte: non garantisconoECCcorretto, assenza di errori sistematici, copertura dell'intero chip o recupero. Il formato RAW rimane quello restituito dal lettore Nikon, compresa la disposizione dei primi record già documentata; nessuna normalizzazione viene applicata.

Il BIN consegnato SHA256 `0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9` resta invariato. Nessun comando inviato alla Nikon, nessuna scritturaSD/flash o acquisizione fisica nuova. Restano memoria/DMA/cache, mount/handoff e recupero fisico; la nuova applicazione fotograficaAkeruOS non ha avviato né prodotto fotografie, circa10% invariato.

Prossimo latoPC: validazione indipendente dei diari/parziali e confronto con dump noti; latofirmware restano le verifiche di residenza e recupero indicate nel checkpointRAM. Il nuovo client è pronto per prove del trasporto quando esista un contesto hardware compatibile e concordato; le prove offline non autorizzano a chiamare installabile il candidato.
