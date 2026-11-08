# NAND dal PC: lettore file TBIB, record17 e limite dello status

21 ottobre 2026 — R0/R3/R4. Continuazione della [selezione fallback](S33_NAND_PC_TBIB_Guardia_Produttore_e_Selezione_Fallback.md). **22 casi CPU offline superati**, con letture e seek sostituiti da fixture locali. Il candidato viene caricato dal lettore RHIR originale, incluso il record17. Il ritorno zero può però seguire una lettura assente quando la RAM contiene già dati con checksum atteso. Non è una procedura di recupero verificata; **NON INSTALLARE**.

## Prove e riproduzione

- [Script](../Python_Trace_Scripts/s33_verify_nand_pc_file_loader.py).
- [Manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/file_loader_cpu_20261021T103612Z/verified_evidence.json), [22 casi](../Risultati/USB_SCSI/Accesso_NAND_PC/file_loader_cpu_20261021T103612Z/file_loader_cases.json), [sostituzioni di laboratorio](../Risultati/USB_SCSI/Accesso_NAND_PC/file_loader_cpu_20261021T103612Z/laboratory_patches.json).
- [Record namespace TBIB](../Risultati/USB_SCSI/Accesso_NAND_PC/file_loader_cpu_20261021T103612Z/tbib_namespace_records.json), [disassemblato lettore](../Risultati/USB_SCSI/Accesso_NAND_PC/file_loader_cpu_20261021T103612Z/gnu_100125c.log), [gestore descrittore](../Risultati/USB_SCSI/Accesso_NAND_PC/file_loader_cpu_20261021T103612Z/gnu_10011bc.log), [montaggio](../Risultati/USB_SCSI/Accesso_NAND_PC/file_loader_cpu_20261021T103612Z/gnu_1008394.log).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_file_loader.py
```

Il motore GNU di base è quello fissato dal runner; questa prova non richiede DSP o nuove build del simulatore. Sorgenti/toolchain GNU e firmware canonico restano in sola lettura. Gli ELF e le modifiche ai soli ingressi simulati sono conservati nella cartella di evidenza. Hash degli input confrontati prima e dopo. Esiste una prova precedente di15casi a101634Z, non ancora pubblicata negli indici: non è stata riscritta. Il checkpoint corrente usa la nuova esecuzione di22casi.

## Formato e trasferimenti

L'ingresso **0100125C** riceve nome volume e path originali. Dopo montaggio01008394 e apertura0100858C legge16byte, verifica RHIR e scorre18descrittori. Il gestore010011BC:

- tipo1: offset e dimensione in settori da512byte, destinazione dal descrittore, confronto della somma originale01001764;
- tipo2: pubblica l'ingresso nella word01041100;
- altri tipi: ritorna zero senza il trasferimento tipo1.

I casi validi con path A e B eseguono **23 letture**:1header,18descrittori e4payload tipo1, indici0/1/8/17. I byte trasferiti vengono confrontati integralmente col TBM del candidato; canary alle destinazioni e stack preservati. Il tipo2/record16 pubblicaBB540; il lettore continua poi sul record17 e ne verifica il checksum. Non viene eseguito l'handoff.

Il pacchetto pubblico completo viene respinto con status11 al magic: il file fallback deve iniziare con RHIR. Questa distinzione era già indicata nel [rapporto statico](boot_recovery.md), ora è eseguita. Nessun file fallback è stato creato sullaSD.

## Esiti ed errori osservati

| Condizione della fixture | Status originale |
|---|---:|
|montaggio fallito|8|
|apertura fallita|9|
|header o descrittore corto|10|
|pacchetto pubblico al posto di RHIR|11|
|checksum payload0 o record17 alterato|13|
|payload0 assente/corto, destinazione inizialeA5|13|
|record17 assente/corto, destinazione inizialeA5|13|
|payload0 assente ma già valido inRAM|0|
|record17 assente/corto ma già valido inRAM|0|
|lettura header/payload completa con status errore|0|
|close o unmount falliti dopo caricamento valido|0|
|seek con status errore ma posizione aggiornata dalla fixture|0|

La routine010011BC chiama seek/read/seek a010011E2/1F8/20E/222 e confronta poi la somma della **memoria di destinazione** a0100122A..232. Non controlla localmente ritorni e conteggio della lettura payload.0100125C controlla il conteggio16 per header/descrittori, ma non il ritornoI/O di quelle chiamate. Il controllo della lunghezza della fixture non rende questi ritorni controllati dal firmware.

Il caso seek fallito dimostra soltanto che il ritorno non viene propagato: la fixture aggiorna comunque la posizione. Non dimostra il comportamento di un seek fisico fallito senza spostamento. I casi con RAM già valida sono controesempi deliberati, non uno stato hardware osservato. La somma a32bit non è una prova crittografica d'integrità.

Dopo errore sul record17, **01041100 può già contenereBB540** perché il record16 è stato elaborato. Il successo del trasferimento resta distinto dallo status finale; questa prova non dimostra che il firmware ignori lo status e salti comunque.

## Namespace del boot: dato confermato, disponibilità aperta

Il literal01008574 usato dal montaggio01008394 contiene **010421CC**. Il codice calcola un passo0x150 e accede anche al campo+58; nei record iniziali si trovano:

|Indice TBIB|Base record|+8|+19|+30|
|---:|---|---|---|---|
|0|010421CC|DEVNAND:|PMNAND:|A:|
|1|0104231C|DEVSD:|PMSD:|B:|

L'associazione statica B→SD/A→NAND è sostenuta direttamente dai dati TBIB. Nel Main la [tabella già analizzata](S33_Apertura_File_e_Volumi.md) ha ordine opposto: non trasferire gli indici numerici fra i due ambienti. Questa verifica non esegue il resolver0102007C, le inizializzazioni inferiori, FAT o controller; non certifica il supporto fisico disponibile alBootTask.

## Stato e continuazione

Candidato SHA-256 `0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9` invariato, vecchio52f8714d escluso. Nessun comando alla fotocamera o scritturaSD/NAND. Nessun avvio completo, recupero fisico, accesso USB esteso o fotografiaAkeruOS: circa10% funzionale invariato.

Prossimo punto: resolver0102007C e inizializzazione/montaggio della tabellaTBIB fino al driverSD, poi significato fisico delle guardie e handoff con stato conservato. Restano durata dell'estensioneRAM, recupero e integritàUSBfisica. L'obiettivo accesso NAND dalPC oppure aggiornamento installabile rimane aperto.

## Continuazione — resolver e creazione SD

La [verifica successiva](S33_NAND_PC_TBIB_Resolver_e_Creazione_Dispositivo_SD.md) riutilizza141casi resolver e aggiunge12casi sulla creazione originale e sul dispatch della callbackSD. B: risolve indice1, il wrapperSD riceve dispositivo0; creazione riuscita e stato del supporto restano distinti. Backend fisico, mount completo e recupero ancora aperti.
