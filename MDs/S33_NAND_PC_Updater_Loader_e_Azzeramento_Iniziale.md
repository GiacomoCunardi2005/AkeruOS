# NAND dal PC: updater, loader e azzeramento iniziale

> **Superato: difetto trovato nel contenitore qui discusso.** Il candidato52f8714d…bc9ac9 e i precedenti con offset spostati sono esclusi: i caricamenti differiti usavano ancora offset fissi originali. I test qui restano validi soltanto nel loro ambito. Leggere la [correzione e le nuove prove](S33_NAND_PC_Offset_Differiti_Corretti_e_Client_Linux.md).

21 ottobre 2026 — R0/R3/R4. Continuazione del [candidato offline](S33_NAND_PC_Parser_Buffer_Privato_e_Contenitore_Offline.md). Il contenitore passa i controlli originali dell’updater eseguiti qui; il loader TBIB originale carica l’estensione e ne verifica il checksum. Codice e buffer aggiunti sopravvivono all’azzeramento iniziale provato. **Il candidato resta NON INSTALLARE:** nessun accesso fisico esteso o aggiornamento pronto è ancora dimostrato.

## Fotocamera collegata: MSDC confermato, enumerazione cambiata

L’utente ha comunicato «connessa la cam». La [raccolta delle09:12:55UTC](../Risultati/Hardware/MSDC_Default/20261021T091255Z/observation.json) contiene10campioni:

| Campioni | Osservazione Linux |
|---|---|
|0–1|Nikon04b0:035d, bus003/device035, interfaccia08/06/50, usb-storage, sda/sda1|
|2|Nikon assente dalla scansione|
|3|stessa identità e percorsoUSB, device038, MSDC, senza disco ancora elencato|
|4–9|device038, MSDC, sda/sda1|

Il disco Nikon misura **45.056settori×512=23.068.672byte=22MiB**; la partizione45.001settori. I descrittori cached sono identici nelle nove osservazioni presenti, SHA256`08081ba5216c46c427b752c0f86d7d7e5c3339e0481e28cc29a4690d419ec6b6`. La variazione del numero dispositivo e il campione assente sono osservazioni, non una diagnosi di cavo, alimentazione o firmware. Non descrivere questa raccolta come dieci campioni stabili.

L’agente ha letto enumerazione, descrittori cached, sysfs e metadati Linux. Non ha aperto settori grezzi né inviato comandi vendor, flash o scritture. **MSDC è attivo; l’identità esatta della flash installata non è stata riletta.** La capacità22MiB non equivale alla restante NAND accessibile. [Revisione della raccolta](../Risultati/Hardware/MSDC_Default/20261021T091255Z/review.json).

## Identità del candidato

Il file verificato è lo stesso [contenitore precedente](../Risultati/USB_SCSI/Accesso_NAND_PC/container_20261021T090006Z/S33_NAND_PC_RAW_OFFLINE_NON_INSTALLARE.bin),29.606.692byte, SHA256:

```text
52f8714dcb9612dec0c6af9363309364de305a9f4eb761edfc9ff92b63bc9ac9
```

Questa fase non lo ha modificato. L’estensione proposta rimane`[35BC00,35CE00)`, con handler35BD40, buffer`[35C0A4,35C8E4)` e controlloCDB35CC00. Le prove leggono il contenitore canonico; le sostituzioni dei servizi avvengono soltanto nelle copie RAM di laboratorio.

## Controlli originali dell’updater

[Script](../Python_Trace_Scripts/s33_verify_nand_pc_updater.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/updater_cpu_20261021T090806Z/verified_evidence.json), [sette validazioni](../Risultati/USB_SCSI/Accesso_NAND_PC/updater_cpu_20261021T090806Z/validation_cases.json), [undici casi writer](../Risultati/USB_SCSI/Accesso_NAND_PC/updater_cpu_20261021T090806Z/writer_cases.json).

Sono eseguiti il checksumXOR12B060 sul file completo con ABI`r0=file+4,r1=lunghezza−4`, la ricerca12AFF0 dei tre descrittori esterni e la validazioneMain12AEA0. I tre header rilocati corrispondono ai76byte del file. Il getter originale16F41C restituisce capacitàMain19.267.584byte usando la tabellaP1IDSTR fornita nei dump e la geometria decodificata da25D194 con inputF0 esplicito. Il candidatoTBM17.619.968byte è accettato; oltre capacità viene restituito01C00114, firma/checksum errati01C00111.

**Limite trovato nel validatoreMain:** a12AF00 un tipo diverso da1 salta a12AF26; l’avanzamento del puntatore descrittore a12AF24 avviene soltanto dopo il tipo1. Il contatore continua, ma il puntatore resta sul primo tipo0. Nel contenitore corrente il validatore controlla quindi i payload0/1 e non raggiunge il successivo tipo1/8. Alterazioni ai payload4 e8 vengono accettate dal solo12AEA0; alterazioni0/1 sono rifiutate. Non attribuire all’updater una validazione integrale delle16somme. Il builder ha controllato tutte16 separatamente; il loader sotto verifica anche il tipo1/8.

Il writer originale1EEA4C, preparatore260FE4 e selettore1EE730 sono eseguiti fino al backend1EDED8 sostituito da un registratore. La tabellaP1IDSTR da244byte deriva daNANDP1.dmp, offset231A; non è una nuova tabella inventata. PerMain: base logica165×64=10560pagine, capacità147×64=9408pagine da2048byte.

| Richiesta | Operazioni registrate |
|---|---|
|nuovoTBM17.619.968byte|legge e prepara la pagina parziale19163; richiede prima quella pagina, poi8603pagine dalla10560|
|vecchia lunghezza17.615.360byte|pagina parziale19161, poi8601pagine dalla10560|
|capacità intera19.267.584byte|9408pagine dalla10560, senza pagina parziale|
|19.269.632byte|01B00116, nessuna lettura parziale o chiamata al backend di scrittura|

La coda del nuovoTBM occupa1024byte dell’ultima pagina: il preparatore conserva gli altri1024byte, inizializzatiA7 dalla fixture di lettura. Controllati anche errore lettura, backend, lock e release, richieste2048/512/0byte, bilanciamento del lock eSP. Un errore del backend sulla pagina finale impedisce la richiesta del corpo centrale. **Nessuna cancellazione, programmazione o rilettura NAND fisica viene eseguita:** lettura parziale, scrittura, flush e mutex sono recorder. Non è stata eseguita l’intera UI dell’aggiornamento con i suoi retry e readback.

Il dispatcher dell’aggiornamento distingue TBM, TBIB eP1RES. Il fatto cheTBIB/P1RES siano identici agli originali non prova che vengano saltati durante l’installazione. L’updater residente e la selezione di recupero fisica restano da stabilire; queste prove usano corpiV1.1 locali.

## Loader TBIB originale sul contenitore ampliato

[Nuovo script](../Python_Trace_Scripts/s33_verify_nand_pc_loader.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/loader_cpu_20261021T091924Z/verified_evidence.json), [cinque casi](../Risultati/USB_SCSI/Accesso_NAND_PC/loader_cpu_20261021T091924Z/loader_cases.json).

Il percorso originale010010C0→01001048 attraversa i17recordRHIR. Soltanto0100A120 è sostituito da un lettore di settori dalTBM locale, che usa memcpy originale0100ABC0. Descriptor reader, checksum01001764 e helper ABI restano originali. Le destinazioni sono inizializzateA5 con16byte di guardia alla fine di ogni payload.

| Lettura | Settore | Settori | Destinazione |
|---|---:|---:|---|
|header|0|1|stack del chiamante di laboratorio|
|payload0 ampliato|1|5499|AD800|
|payload1|5500|1599|360800|
|payload8|18003|3|C8E800|

Esito valido0: i tre payload caricati sono identici a quelli del candidato, guardie intatte eSP ripristinato. Il record16 di tipo2 scriveBB540 nella cella01041100. Sono provati anche firmaRHIR alterata→11 dopo la sola letturaheader; checksum0 alterato→13 dopo aver copiato il payload0; errore della seconda lettura→7 senza copiarlo. Gli altri payload restanoA5 nei casi che si interrompono prima del loro caricamento.

La prova positiva chiude il dubbio locale sul descrittore esteso: il loader usa il nuovo conteggio5499 e carica tutta l’estensione. Non dimostra il controllerNAND, la traduzione fisica o il reset daROM.

## IngressoMain e azzeramento limitato

Il quinto caso completa lo stesso caricamento, poi entra aBB540. Il prefissoCPU e il runtimeAD890→AD90C→13A954 sono eseguiti. Due confini sono espliciti:330A78, configurazioneCPU non provata qui, ritorna da uno stub;333D7C registra il contesto e termina il test prima del kernel. Le due sostituzioni vengono scritte nella sola RAM di laboratorio **dopo** la verifica dei checksum del loader.

Osservati: guardia3707B8 caricata dal payload1 nonzero; intervallo`[42D140,5DA5DC)` interamente azzerato;SP5DADC4 all’ingresso del kernel dopo le due push del runtime;gp423844. Il secondo intervallo di azzeramento ha lunghezza0. Tutti i byte del payload0, salvo le due sostituzioni dichiarate, coincidono con il candidato: **estensione35BC00..35CE00 e buffer privato preservati**. La guardia dopo lo stack rimaneA5.

Questo verifica il caricamento e il primo azzeramento, senza provare durata successiva, scrittori calcolati, allocazioni, overlay, cache, DMA, scheduler o concorrenzaUSB. L’intervallo aggiunto non diventa RAM assegnata in modo generale.

## Riproduzione e limiti

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_updater.py
python3 Python_Trace_Scripts/s33_verify_nand_pc_loader.py
```

I manifest conservano hash di firmware/dump/candidato, strumenti, sorgenti degli script e snapshot. Le build GNU esistenti sono usate in sola lettura. Il motoreDSPv7 è necessario per il limitato prodotto positivo del helper settori0103ECBC e per i prodotti del writer; non è una certificazione completa delle istruzioniARC700. I primi tentativi del loader con il motore base si sono arrestati su istruzione non supportata nel helper e restano conservati comeFAIL, senza essere reinterpretati come difetti del candidato. Nel validatore pacchetto il primo tentativo aveva usato l’intervalloXOR errato; l’esecuzione riuscita usa l’ABI sopra specificata.

Prossimo punto giustificato: controllare la durata dell’estensione rispetto ad allocazioni/scrittori e caricamenti successivi, poi completare il clientPC e il percorso di lettura verificabile. Restano updater residente, errore/recupero fisico e identità runtime. L’obiettivo rimane attivo; circa10% funzionaleAkeruOS invariato.
