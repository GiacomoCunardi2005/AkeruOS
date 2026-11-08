# NAND dal PC: offset differiti corretti e client Linux

21 ottobre2026 — R0/R3/R4. Continuazione di [updater e loader](S33_NAND_PC_Updater_Loader_e_Azzeramento_Iniziale.md). **Corretto un difetto concreto del contenitore precedente.** Il nuovo mantiene gli offset Nikon e carica l’aggiunta con un record separato. Un clientLinux legge una paginaRAW tramiteSG_IO, verificato soltanto offline. L’obiettivo non è ancora raggiunto: nessuna lettura fisica estesa e nessun aggiornamento dichiarato pronto da installare.

## Difetto trovato e candidati precedenti esclusi

Il candidatoSHA256`52f8714dcb9612dec0c6af9363309364de305a9f4eb761edfc9ff92b63bc9ac9` ampliava il payload0 e spostava i15successivi di4608byte. I descrittoriRHIR erano aggiornati, ma i wrapperC2/C3/C4/Resource contengono **offset letterali nel fileTBM**, già ricostruiti nel [rapporto dei gruppi](S33_Gruppi_C2_C3_C4_Risorse_e_Segnali_Caricamento.md). Quei valori erano rimasti originali.

| PoolCPU | Payload | Offset richiesto dal wrapper | Posizione nel vecchio candidato |
|---|---:|---:|---:|
|C5990|2|376600|377800|
|C599C|3|3E0400|3E1600|
|C5A30|4|4FB600|4FC800|
|C5A40|5|5FB800|5FCA00|
|C5AD4|6|707600|708800|
|C5AE4|7|8C2A00|8C3C00|
|C5B58|9|8C9A00|8CAC00|

Il loader iniziale legge i descrittori; questi wrapper leggono invece i valori nei pool. I precedenti testBOT, checksum e loader verificavano i rispettivi percorsi, **non i trasferimenti differiti**. Le prove rimangono conservate col loro ambito; non rendono valido quel contenitore per l’avvio completo. [Rigetto riproducibile del vecchio candidato](../Risultati/USB_SCSI/Accesso_NAND_PC/deferred_cpu_20261021T093735Z/old_candidate_rejection.json), [disposizione corrente dei candidati](../Risultati/USB_SCSI/Accesso_NAND_PC/candidate_disposition.json). Nessuno di questi file è stato installato dall’agente.

## Nuova disposizione, senza spostare i payload Nikon

Il [builder corretto](../Python_Trace_Scripts/s33_build_nand_pc_offline.py) conserva dimensioni e offset di tutti i16payload originali, i gap, la coda originaleTBM e il record16 di tipo2. Restano le tre modifiche funzionali già verificate: defaultMSDC, hook del parser e puntatoreFF. L’aggiunta4608byte viene accodata alTBM:

| Elemento | Nuovo valore |
|---|---|
|Numero recordRHIR|18, prima17|
|Record17, prima inutilizzato|tipo1, sorgenteTBM17.615.360byte/settore34405,9settori|
|Destinazione record17|35BC00..35CE00 escluso|
|Payload0|dimensione originale2AE400, senza estensione nel file|
|Ingresso record16|BB540, invariato|

L’ordine del loader diventa0,1,8, poi ingresso16 memorizzato, poi aggiunta17. Il test CPU esegue realmente il caso successivo al record d’ingresso; non presume che il nuovo record venga caricato.

[Nuovo contenitore NON INSTALLARE](../Risultati/USB_SCSI/Accesso_NAND_PC/container_20261021T092600Z/S33_NAND_PC_RAW_OFFLINE_NON_INSTALLARE.bin),29.606.692byte, SHA256:

```text
0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9
```

[Manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/container_20261021T092600Z/verified_evidence.json):17somme dei payload, KHIR, XORpacchetto, descrittori esterni, TBIB/P1RES identici e rollback esatto al file originale. La dimensione complessiva e il margine logicoMain1.647.616byte non cambiano. Il builder ora verifica anche le sette triplette dei wrapper contro le posizioni effettive dei byte. Gli indirizzi di codice/buffer/hook restano quelli già eseguiti dalle30transazioniBOT e dalle256lunghezzeCDB.

## Prove eseguite sul nuovo file

- [Updater](../Risultati/USB_SCSI/Accesso_NAND_PC/updater_cpu_20261021T092645Z/verified_evidence.json): XOR originale sull’intero pacchetto, tre header, sette casi validatoreMain e undici writer. BackendNAND/lettura parziale/mutex/flush restano registratori. Rimane il limite del validatoreMain al primo tipo0, spiegato nel rapporto precedente.
- [Loader](../Risultati/USB_SCSI/Accesso_NAND_PC/loader_cpu_20261021T092645Z/verified_evidence.json): sette casi, adesso cinque letture nel successo — header e payload0/1/8/17. Controllati anche checksum errato della nuova aggiunta e fallimento della sua lettura:13 e7, senza accettare il caricamento come completo. Il casoBB540→azzeramento iniziale conserva l’aggiunta, conCPUsetup e kernel ai confini di laboratorio già dichiarati.
- [Trasferimenti differiti](../Risultati/USB_SCSI/Accesso_NAND_PC/deferred_cpu_20261021T093735Z/verified_evidence.json), [script](../Python_Trace_Scripts/s33_verify_nand_pc_deferred_loads.py): quattro wrapper originali, modalità10 esplicita; le sette richieste copiano i byte reali del nuovoTBM con memcpyTBIB originale. Ogni destinazione coincide integralmente col relativo payload, guardie16byte eSP intatti. L’aggiunta e il restoMain0 non cambiano fuori dalle sei sostituzioni dichiarate. I servizi profiler/lock/configurazione/eventi/release sono recorder; il lettore è una copia da file, non il controllerNAND.

La verifica degli [intervalli dichiarati](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_interval_audit.json) separa l’aggiunta dai16payload Nikon, dall’azzeramento iniziale e dal poolkernel noto. È un controllo geometrico dei descrittori/configurazione, non una dimostrazione di tutti gli scrittori calcolati o allocatori futuri. I caricamenti10 e11–15 non sono eseguiti nel test differito; i loro offset e destinazioni dichiarati rimangono originali.

## Client PC di sola lettura

[Client](../Python_Trace_Scripts/s33_nand_pc_read.py), [verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_client.py), [esito](../Risultati/USB_SCSI/Accesso_NAND_PC/pc_client_20261021T093222Z/verified_evidence.json).

Usa soltanto librerie standardPython eSG_IO Linux. Apre il dispositivo in sola lettura e controlla l’identità tramite il descrittorefile effettivamente aperto e sysfs:04b0:035d, interfaccia08/06/50, LUN0. Accetta un dispositivoSCSI generico o disco intero; rifiuta file regolari, altro produttore, PTP oLUN diverso. Non seleziona automaticamente un disco.

Costruisce soltanto ilCDB16`FF AKRN 01 chip page block_BE16 zero[6]`, direzioneIN e lunghezza2112. Controlla coordinate nel profilo configurato, statusSCSI/host/driver, indicatoreerrore e residuo esattamente0. Errori o dati corti non producono un risultato. Il file locale esistente non viene sovrascritto. I byte restano nel layoutRAW Nikon restituito: nessuna normalizzazione o nuova certificazioneECC.

Le prove controllano ABI completo`sg_io_hdr_t` rispetto all’headerLinux locale mediante compilazioneC;30CDB del client vengono decodificati dal nucleoC effettivo del firmware; sei limiti coordinate e sette erroriSCSI/residuo vengono rifiutati. Verificati identificazione con sysfs di laboratorio e conservazione/rimozione corretta dei file locali. Nessun dispositivo reale viene aperto dai test.

La forma del futuro comando è:

```text
python3 Python_Trace_Scripts/s33_nand_pc_read.py --device /dev/sgN --block BLOCCO --page PAGINA --output pagina.raw
```

È documentazione dell’interfaccia, **non una richiesta di esecuzione con il candidato attuale NON INSTALLARE**. Il client richiede un handlerAKRN compatibile effettivamente installato; non è stato eseguito sulla fotocamera. I permessiLinux e l’eventuale requisitoCAP_SYS_RAWIO per l’opcodevendor non sono stati verificati sul dispositivo. È una lettura di pagina arbitraria, non un programma di estrazione automatica dell’intero chip.

## Continuazione

Il difetto degli offset è corretto e coperto da una nuova prova di trasferimento. Restano da chiudere durata e usi calcolati dell’intervallo aggiunto, percorso dell’updater residente e recupero fisico, poi provaUSB/NAND e confronto d’integrità sulle pagine reali. Ultima osservazionehardware resta quella09:12UTC descritta nel rapporto precedente:MSDC22MiB con breve assenza/nuova enumerazione. Nessuna nuova scritturahardware o flash, nessun avvio/fotoAkeruOS; circa10% invariato.

## Continuazione — componenteMain fino al confronto

Il [rapporto successivo](S33_NAND_PC_Main_Updater_Rilettura_Retry_e_Limite_Recupero.md) esegue12AD58 con writer/preparatori e rilettura/confronto originali su modelloRAM:12casi, retry, mismatch all’ultimo byte e possibili modifiche già effettuate in caso di errore finale. Non è il dispatch dell’intero pacchetto né recupero fisico; candidato invariato, NON INSTALLARE.
