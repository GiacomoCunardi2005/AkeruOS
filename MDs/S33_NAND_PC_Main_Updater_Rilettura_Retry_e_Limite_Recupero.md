# NAND dal PC: updater Main, rilettura, retry e limite del recupero

21 ottobre2026 — R0/R3/R4. Continuazione di [offset corretti e clientLinux](S33_NAND_PC_Offset_Differiti_Corretti_e_Client_Linux.md). **La routine originale di aggiornamentoMain ora passa dodici casi con scrittura, rilettura e confronto su un modelloRAM.** Gli errori persistenti terminano dopo tre tentativi; il contenuto può essere già modificato quando viene restituito un errore. Non è una prova di recupero fisico e il candidato rimane **NON INSTALLARE**.

## Candidato e prove

Il candidato è invariato: SHA256`0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9`, [manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/container_20261021T092600Z/verified_evidence.json). I vecchi contenitori con offset differiti incoerenti restano esclusi; non vengono rivalidati da questo lavoro.

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_main_update.py).
- [Evidenza riuscita](../Risultati/USB_SCSI/Accesso_NAND_PC/main_update_cpu_20261021T094628Z/verified_evidence.json), [dodici casi e contatori](../Risultati/USB_SCSI/Accesso_NAND_PC/main_update_cpu_20261021T094628Z/update_cases.json).
- [Confini sostituiti nel solo laboratorio](../Risultati/USB_SCSI/Accesso_NAND_PC/main_update_cpu_20261021T094628Z/laboratory_patches.json).
- [RoutineMain originale](../Risultati/USB_SCSI/Accesso_NAND_PC/main_update_cpu_20261021T094628Z/0012ad58_gnu.txt), [rilettura](../Risultati/USB_SCSI/Accesso_NAND_PC/main_update_cpu_20261021T094628Z/001ecd6c_gnu.txt), [preparatore lettura](../Risultati/USB_SCSI/Accesso_NAND_PC/main_update_cpu_20261021T094628Z/00260320_gnu.txt), [confronto](../Risultati/USB_SCSI/Accesso_NAND_PC/main_update_cpu_20261021T094628Z/0032e508_gnu.txt).

Riproduzione:

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_main_update.py
```

## Percorso eseguito

L’ingresso12AD58 riceve callback, puntatoreTBM reale del candidato, lunghezza17.619.968byte e buffer di rilettura distinto. Esegue:

1. Validatore12AEA0 originale, con capacità dal getter16F41C.
2. Writer1EEA4C originale, preparatore260FE4 e selettore1EE730. Per il candidato: pagina finale parziale19163, poi8603pagine dalla10560, come nel test inferiore precedente.
3. Rilettura1ECD6C originale: arrotondamento a34414settori, preparatore260320, controllo di capienza e calcolo della baseMain.
4. Confronto32E508 originale sull’intera lunghezzaTBM, senza sostituirlo con un hash o un ritorno di successo.
5. Ramo di errore e contatore originale dei tentativi, fino al limite3.

Le quattro finestre pubblicate coincidono con il firmware originaleV1.1, con i byte alle medesime posizioni nel candidato e con quelli del MainCode fornito dall’utente. Questo confronto documenta l’identità delle routine nei file disponibili; **non è una nuova rilettura della flash attualmente installata**.

## Cosa rappresenta la NAND nel test

La memoria a6000000 è un fileRAM da19.267.584byte, inizialmenteA7; non è un’immagine valida del firmware precedente né una NAND emulata. Il buffer di rilettura è a8000000, inizialmenteA5. Entrambi hanno16byte finali di guardia.

Sono sostituiti soltanto mutex, flush e tre confini di trasferimento:

| Confine | Effetto nel modello |
|---|---|
|1ED11C|legge pagine relativeMain nella RAM, per le parti finali di writer/reader|
|1EDED8|registra la richiesta e copia le pagine nella RAM, oppure restituisce l’errore iniettato|
|1ECD14|registra e copia il corpo della rilettura dalla RAM, oppure restituisce l’errore iniettato|

Le copie dei recorder usano memcpyTBIB originale0100ABC0. Preparazione e ricomposizione delle porzioni da512byte restano nei corpi Nikon. La geometria è decodificata dal firmware con inputF0 esplicito eP1IDSTR dai dump, non misurata sulla macchina. Il motoreDSPv7 esistente è usato in sola lettura nel dominio ristretto dei prodotti positivi già dichiarati. Non è attivo il tracking generale delle letture RAM sconosciute.

Il modello non esegue erase, bad-block mapping, ECC, programmazione parziale, tempi del controller, perdita di alimentazione o persistenza. Un errore del recorder di scrittura è iniettato prima della copia; **non prova che una scritturaNAND reale fallita lasci invariati i byte**.

## Dodici esiti verificati

| Caso | Tentativi writer | Riletture del corpo | Ritorno12AD58 | Notifiche |
|---|---:|---:|---|---|
|normale|1|1|0|4,5,6|
|callback nullo|1|1|0|nessuna|
|errore pagina finale persistente|3|0|01C00112|4|
|errore pagina finale una volta|2|1|0|4|
|errore corpo persistente|3|0|01C00112|4|
|errore rilettura persistente|3|3|01C00112|4,5|
|errore rilettura una volta|2|2|0|4,5|
|primo byte diverso persistente|3|3|01C00112|4,5,6|
|primo byte diverso una volta|2|2|0|4,5,6|
|ultimo byte diverso una volta|2|2|0|4,5,6|
|firmaRHIR errata|0|0|01C00111|nessuna|
|lunghezza oltre capacità|0|0|01C00114|nessuna|

Nei successi, RAMscritta e buffer di rilettura coincidono integralmente con ilTBM candidato, comprese aggiunta e ultima pagina parziale. La prova sull’ultimo byte inietta la differenza aoffset17.619.967: il confronto la rileva e richiede una seconda scrittura/rilettura. Tutti i casi preservanoSP e guardie; i lock sono rilasciati e i byte dopo la lunghezzaTBM rimangonoA7.

Il limite già trovato nel validatore12AEA0 rimane: non controlla tutti i payload dopo il primo tipo0. Il confronto finale qui provato riguarda invece tutti i byte della lunghezza fornita; non va confuso con la validazione dei contenuti prima della scrittura.

## Implicazioni per errore e recupero

**Le notifiche non sono un certificato di successo.**12AD8C invia4 prima del ciclo. Solo nel primo tentativo,5 segue il writer e6 segue la rilettura;6 precede il confronto32E508. Nel caso di mismatch persistente compare quindi4,5,6 ma il ritorno finale è01C00112. Dopo un primo tentativo fallito, un secondo può riuscire senza emettere5/6: è il comportamento originale verificato, non una nuova UI proposta.

**Errore finale e contenuto già modificato possono coesistere.** Con errore persistente sul corpo, il modello contiene la nuova codaTBM mentre il prefisso restaA7. Con errore persistente di rilettura o mismatch, la RAMscritta contiene già l’intero candidato, pur con ritorno01C00112. La funzione restituisce un esito generale; non restituisce al chiamante i codici2345/3456 iniettati nei backend.

Questa routine non richiede il ripristino dell’immagineMain precedente nei percorsi provati. Ciò non esclude eventuali meccanismi nel driver inferiore o altre copie fisiche: **non sono simulati o dimostrati qui**. Tre tentativi non equivalgono a rollback o a recupero dopo interruzione.

## Stato e continuazione

È chiusa la verifica locale del componenteMain da validazione a confronto/retry. Non è ancora eseguito l’intero12A794 con registrazione nomi, dispatcherBC3F8 e componentiBootCode/P1RES. Il [rapporto storico sul percorso pubblico](SD_UPDATE_RECOVERY_PATH.md) li collega staticamente; non assumere che ilTBIB invariato venga saltato. La precedente indicazioneV1.0 in quel rapporto è storica: le [foto successive](S33_HiddenMenu_Hardware_Foto_e_Versioni.md) mostranoMAIN1.1100/BOOT0.1380, senza sostituire una lettura attuale del codice residente.

Prossimo punto concreto: eseguire il dispatch del contenitore e delimitare le richieste sui componenti invariati, poi raccordare fallbackTBIB e condizioni del recupero. Restano durata RAM, controller/cache/concorrenza e integrità delle pagine fisiche. Nessun aggiornamento installato o comando inviato alla Nikon, candidato invariato e **NO-GO**. Obiettivo ancora attivo; circa10% funzionaleAkeruOS invariato.

## Continuazione — dispatch del pacchetto eseguito

La [verifica successiva](S33_NAND_PC_Dispatch_Pacchetto_Boot_Invariato_e_Contatore.md) esegue anche registrazione,12A794/BC3F8 e callback dei tre componenti su recorder: richiestaBoot anche quando invariato; contatore conservato dopo errore può causare conclusione prematura nella seconda chiamata diretta. Dieci casi, nessuna provaUI o hardware; NO-GO invariato.
