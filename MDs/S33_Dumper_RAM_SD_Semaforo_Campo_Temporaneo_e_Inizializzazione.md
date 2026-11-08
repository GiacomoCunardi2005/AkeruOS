# Dumper RAM: semaforo SD, campo temporaneo e inizializzazione

23 ottobre 2026, R0/R1/R4. Continuazione del [binding SD](S33_Dumper_RAM_Binding_SD_ABI.md) e del [ciclo di vita degli handle](S33_Dumper_RAM_SD_Handle_Errori_e_Chiusura.md). **22 casi sul codice originale V1.1** collegano il campo temporaneo del contesto all'inizializzazione e alla sincronizzazione. Nessuna fotocamera, SD o NAND coinvolta.

Il contesto viene azzerato all'allocazione e il semaforo di accesso viene inizializzato a1. Il percorso `d` modifica temporaneamente il campo a offset760 e lo ripristina prima del rilascio; `n` lo conserva. Il futuro binding non può acquisire quel semaforo e poi richiamare un'apertura che lo acquisisca nuovamente: la seconda wait dello stesso task si accoda.

## Prove e portata

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_mutex.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDMutex.java).
- [Manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mutex/20261022T232905Z/verified_evidence.json), [22 esiti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mutex/20261022T232905Z/trace.txt), [18 finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mutex/20261022T232905Z/gnu_verified.txt), [log](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mutex/20261022T232905Z/headless.log), [ricerca limitata degli store](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mutex/20261022T232905Z/bounded_store_candidates.json).

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_mutex.py
```

| Gruppo | Casi | Codice eseguito e confini |
|---|---:|---|
| helper `n`/`d` |14|helper e resolver originali; wait/post, parser nome, creazione e allocazione file sono recorder/fixture|
| semaforo |4|wait23ECA4 e post23EE48 originali; kernel/task e liste predisposti; stop prima dello scheduler B2D50|
| costruttore |4|1F3554,268EE4,269F1C,AD90C,13A954,23EA7C,1786E8 e179354 originali; allocazione inferiore, metadati, registrazione, free e allocazione secondaria simulati|

Gli input canonici, i sorgenti e gli snapshot sono verificati tramite hash. Gli alberi GNU sono soltanto letti/eseguiti. I gruppi separati non costituiscono una sessione FAT completa e non dimostrano concorrenza fisica.

## Campo a offset760 e serializzazione

La tabella del parser1F455C associa `d` a1F4624 e quindi2A1858; `n` raggiunge2A1648. Entrambi usano2A1300: `[handle]→device`, `[device+0x24]→context`, wait su **context+388 (0x184)** via23ECA4, controllo **context+0x40**. Se il contesto non è pronto, il resolver esegue post e rifiuta l'operazione. Il rilascio2A1398 inoltra a23EE48.

Nel percorso `d`, dopo il parser29FFB0, se il nome interpretato inizia con backslash seguito da un byte non nullo, **2A18C8 scrive1 a context+760 (0x2F8, campo190 scalato)**. La chiamata2AC2B4 avviene ancora sotto quel semaforo. **2A18EA scrive0 dopo il ritorno della creazione**, anche nel caso di collisione simulata; il post è successivo, da2A191A. Anche i nomi relativi e la sola radice raggiungono questo azzeramento finale; con campo iniziale1 il caso relativo viene quindi riportato a0.

Nel percorso `n`, la chiamata2AC2B4 avviene sotto lo stesso oggetto di sincronizzazione, con r6=0, ma **non azzera il campo**: valore iniziale1 rimane1. I casi di collisione sono esiti forniti dal confine2AC2B4; non sono nuove esecuzioni complete del lookup. La precedente prova statica2ABCD4/2ABD0E conserva il suo limite: la guardia sul nome esatto è attiva quando quel campo vale0.

La conclusione circoscritta è che questi due helper non osservano contemporaneamente il campo temporaneo se rispettano la stessa wait/post. Non è dimostrata l'assenza di altri scrittori, alias o modifiche durante mount/unmount.

## Il semaforo non è ricorsivo

23ECA4 legge il conteggio a **semaphore+0x18**, magic **0x6C77736D a+0x14**. Con conteggio positivo lo decrementa. Con0 prepara task state0x42B, task+0x30→lista waiter, accoda il nodo task+188, incrementa il numero waiter e raggiunge B2D50. Non compare un bypass basato sul proprietario del semaforo.

| Conteggio iniziale e sequenza | Esito originale |
|---|---|
|0, wait|si accoda prima del ritorno|
|1, wait→wait nello stesso task|prima ritorna0, seconda si accoda|
|2, wait→wait|entrambi ritornano, conteggio finale0|
|1, wait→post→wait|tre ritorni0, conteggio finale0|

Nel caso senza waiter il post incrementa il conteggio. Non viene eseguito uno scheduler né consegnato un interrupt. Il termine storico «mutex» descriveva l'uso come lock; la primitiva provata è un **semaforo a conteggio inizializzato a1**, senza proprietà ricorsiva dimostrata.

## Costruzione e valori iniziali

**1F3554** richiede852 byte a268EE4. L'allocatore inferiore2E4EC4 è una fixture che fornisce storage esplicito oppure nullo. Con puntatore non nullo, l'allocatore originale esegue **269F1C→AD90C→13A954(ptr,0,852)**: tutti gli852 byte riempiti inizialmente con0xA5 risultano0 prima della registrazione; le guardie di16 byte ai lati restano intatte.

La registrazione2A3C5C riceve il contesto inr7. Su ritorno0, **1F35A6 chiama23EA7C(context+388,1)**. Il costruttore del semaforo è originale: conteggio1, magic corretta, lista waiter vuota e inserimento nella lista globale kernel+0x23C, numero oggetti incrementato. Al termine **context+760 e context+0x70 sono0**; il campo ready+0x40 resta inizialmente0. I campi+420 e+0 conservano gli input del costruttore, mentre+416 riceve l'allocazione secondaria. Questo prova lo stato del contesto appena costruito; non prova quale montaggio successivo avvenga.

| Caso | Ritorno e stato osservato |
|---|---|
|allocazione principale e registrazione riuscite|0, semaforo1, campi760/0x70 a0, nesting critico finale0|
|allocazione secondaria nulla|**ritorno0**, context+416=0, semaforo1, nesting0: nessun controllo locale del nullo|
|registrazione fallita simulata|ritorno01A00002, richiesta free, nessun semaforo registrato; nesting originale task+0x68 finale1|
|allocazione principale nulla|01A00006, nessuna registrazione/free, area candidata invariata0xA5, nesting0|

Le primitive critiche1786E8/179354 sono realmente eseguite nei quattro casi. Il nesting1 sul ramo di registrazione fallita è una proprietà del corpo esaminato **con registrazione e free simulati**, che non modificano il kernel. Non basta per diagnosticare un difetto globale: gli effetti dei due servizi reali e l'eventuale gestione del chiamante rimangono fuori prova. Analogamente, il nullo secondario con ritorno0 impone di seguire i consumatori prima di considerare la costruzione una prova di piena disponibilità.

## Ricerca degli scrittori e prossima verifica

La scansione del listato lineare nei soli intervalli1F3000..1F9000 e2A0000..2B0000 trova sette store con offset espliciti compatibili con112/0x70 o760/190. Vengono mantenuti come **candidati**, non sette scrittori del medesimo contesto: gli ultimi due hanno basi non attribuite qui. Copie, memset, alias e indirizzi calcolati non sono coperti. L'azzeramento852 byte qui eseguito è invece una nuova prova positiva di inizializzazione che quella scansione non avrebbe trovato.

Il campo backend+0x70 viene inizializzato a0 ma ha scrittori successivi nel montaggio, compreso il ramo che seleziona7. Per backend7 il parser `n` condivide il percorso di `w`, quindi l'inizializzazione e il semaforo **non rendono automaticamente esclusiva ogni apertura mode3**.

Prossimo: ricostruire i confini di mount/unmount e la stabilità del backend, poi raccordare validazione e creazione senza doppia wait. Restano mappa RAM fisica completa, lifetime launcher e stack, cleanup degli handle e recupero. Il prototipo C e i BIN non sono modificati. **NON_INSTALLARE**, nessun dump RAM reale, circa10% funzionale AkeruOS invariato.

## Continuazione — montaggio e chiusura, 23 ottobre 2026

[16 nuovi casi](S33_Dumper_RAM_SD_Mount_Chiusura_e_Stabilita_Backend.md) eseguono mount1F3EF0 e callback close1F48A4/ramo volume1F46C4. La scelta backend è sotto semaforo ma+424 è pubblicato prima; una query fallita salta il post nel modello. Close backend7 azzera+424 dopo il post, backend1 riacquisisce e controlla la halfword+108. Restano lifetime e livello superiore di sincronizzazione; non è prova di race/deadlock hardware. Prossimo: scrittori+108 e chiamanti close. NON_INSTALLARE.
