# S33 — file FAT: creazione, scrittura, close e riapertura con contesto nuovo

23 ottobre2026, R0/R1/R4. Continuazione dei [motori write/PMSD](S33_Dumper_RAM_SD_Motori_Write_PMSD_e_Rilettura.md). Il nuovo banco esegue ora il filesystem originale sul modello di una partizione FAT12: creazione del file, allocazione FAT, scrittura tramite12DE3C, dati/metadati al controller, close e riapertura con un nuovo kernel e contesto filesystem di laboratorio.

**13 scenari CPU ritornati**, comprendenti successi e negativi attesi. I quattro scenari positivi superano anche `fsck.fat -n`. Il negativo frammentato lascia una catena FAT guasta, rilevata dal parser indipendente e respinta dafsck: il PASS di quel test significa che la corruzione attesa è stata osservata, non che il file sia integro. Il contratto di ritorno write è più debole della precedente descrizione. **NON_INSTALLARE.** Nessuna fotocamera, SD reale, firmware BIN o sorgente GNU/C modificati.

## Riproduzione

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_file_write.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_write_partition.py
```

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_file_write.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDFileWrite.java).
- [13 casi e verifiche indipendenti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/trace.txt), [GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/gnu_verified.txt).
- [Partizione dopo creazione PIO](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/new-exclusive_partition.img), [dopo scrittura513byte](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/new-tail_partition.img), [dopo DMA modellata](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/new-async_partition.img).
- [Controllo positivo](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/new-exclusive_fsck.txt), [negativo FAT guasta](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T185804Z/fragmented-short_fsck.txt).
- [Regressione24 motori/PMSD](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Partition/20261023T185607Z/verified_evidence.json), rieseguita con esito positivo. Nessuna modifica ai probe precedenti.

Il runner verifica16hash,21finestre GNU e17istruzioni chiave; conserva8snapshot sorgente, comando, log, immagini, catture PIO e dati della DMA modellata. Hash delle immagini e dei contenuti ricostruiti sono nelJSON. Firmware originale V1.1:29.602.084byte, SHA256`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Non è una verifica di compatibilità con V1.0.

## Partizione e confine iniziale

La partizione sintetica contiene110settori da512byte,2settori/cluster,20settori riservati, una FAT da80settori,32entry root e4cluster dati. FAT12 eBPB sono coerenti: FAT20, root100, dati102, cluster2..5, settore finale109; hidden sectors2048. Ogni immagine misura56.320byte. L'offset2048 viene applicato dal codice PMSD originale.

Il BPB e il contenuto iniziale sono fixture, così come il contesto filesystem costruito dalla geometria e gli oggetti dispositivo/volume. **Il mount Nikon e il registro generico dei dispositivi non vengono eseguiti.** Nei nuovi file la root è vuota e le entry FAT dati sono libere; nel caso r+ esisteTARGET.BIN da2048byte. Solo la preparazione iniziale scrive direttamente questi settori. Durante il caso i dati della scheda cambiano in seguito agli store PIO originali, oppure alla copia del modello hardware DMA esplicitamente descritta sotto. Non viene inserita dal test una directory finale o una FAT finale attesa.

La cache dei record modificati ha buffer a02012000, capacità8, conteggio0, nei campi contesto+828/+832/+836. Il relativo semaforo1A0001D e quello del volumeB1A0000D sono inizializzati attraverso15933C originale. Gli oggetti cache dei settori e FAT sono predisposti, non ottenuti dal mount.

## Catena eseguita

```text
1F43AC(file-wrapper,path,"n" oppure "r+")
  → backend1 /2A1648 o21A0D0
  → parser/lookup/scanner originali
  → 2AC2B4 /2ABCD4 per creare un nome nuovo
  → 2AC528: oggetto privato e lista file

12DE3C(file,buffer,bytes,selector,&written)
  → 1F1A8C /1F19E0: volume B dalla tabella376018
  → 1593AC /1F1B18: semaforo e controlli volume
  → 1FA090 /1F4958 /21A4B8
  → 1F25D8,2AB770,2AB95C,1F277C: catena/allocazione/FAT
  → 2A0D70 /2A0C14: cluster verso settori
  → PMSD /DEVSD /168410 /25B9C0 o25BB5C
  → comando,risposta,gate,PIO oppure servizio asincrono originali
  → 1F337C: record di directory differito

1F48A4 /21AD30
  → 1F2484: FAT sporca
  → 2AC438: aggiorna entry e trasferisce directory
  → rimozione originale dalla lista e rilascio oggetto privato

NUOVO emulatore, kernel, oggetti e cache predisposti da zero
  → conserva soltanto la scheda risultante
  → 1F43AC(...,"r") /1F3524 /1F48E8
  → FAT/cluster/PMSD/controller originali
  → verifica byte e dimensione, poi close originale
```

Il sorgente noto differenzia i settori: `(k*37+11) XOR ((k>>8)*97)`, troncato a8bit. Vengono confrontati tutti i byte richiesti, le dimensioni nel record della scheda e nel wrapper riaperto, le guardie sorgente/destinazione e quelle degli scratch. Scratch allocati/liberati8/8 o10/10, oggetti privati2/2, lista file torna0 e semafori FS/PM tornano1. Gli allocatori inferiori sono modelli host: queste quantità descrivono le richieste originali osservate, non l'heap fisico Nikon.

Le cache appartenenti al volume restano predisposte fino alla distruzione dell'emulatore. Non viene presentata tale distruzione come close originale del volume o rilascio generale dei suoi buffer.

## Creazione esclusiva nel profilo provato

`n` percorre il backend1 con campo temporaneo760=0, sotto il semaforo filesystem originale. Esegue2ABCD4 oltre la precedente barriera2ABD36, trova una entry libera, costruisce il record e lo scrive mediante la catena del controller. La scrittura del file assegna i cluster e aggiorna la FAT con le istruzioni originali.

Dopo il close il banco ripete l'apertura `n` sullo stesso nome, ancora nello stesso contesto: ottiene01A00011, nessun oggetto/lista file viene pubblicato, nessuno store dati viene emesso e **tutti i110settori restano identici**. La riapertura successiva `r` avviene con un contesto nuovo e ritrova il primo file.

La prova riguarda un nome corto, un task, backend1 e una geometria dichiarata. Non dimostra tutti gli interleaving o l'atomicità del futuro preflight dell'adapter. Backend7 continua a condividere il ramo `n/w`; `x` generaTMP, non ha il significato C11. Queste modalità non vengono promosse a binding universale.

## PIO e DMA: prove differenti

Con selector0 il codice originale legge i buffer ed esegue gli store alla porta. Il modello legge ogni halfword **dopo** `25A43A` e la inoltra alla scheda. Le catture comprendono30.976byte complessivi: dati, FAT, directory e ritentativi; non sono la dimensione dei file creati.

Con selector1 `12DE3C` pubblica temporaneamente il selettore nel record volume+5C. Il codice DEVSD seleziona il servizio asincrono per il profilo raggiunto; il campo viene poi ripristinato a0 prima del close. Anche una lettura FAT interna attraversa il receive asincrono.

Il nuovo banco aggiunge un **modello hardware DMA**:

- write: legge il puntatore programmato nei registriFEE050C/0510 e il conteggio wordFF0002C/30×4; asserisce corrispondenza con il trasferimento originale e legge quella memoria per aggiornare la scheda;
- receive: legge il puntatoreFEE04C8/04CC e verifica lo step dell'oggetto512CC8, copiando i settori selezionati nel buffer programmato;
- esegue poi status/router/walker, dispatcher dati, callback, SET/WAIT/query/CLEAR, deadline e rilascio originali. Non sostituisce il risultato finale del filesystem.

Il caso `new-async` ha1024byte di write DMA modellata e1024byte di read FAT DMA modellata; metadati e rilettura con contesto nuovo passano daPIO. Non si attribuisce la copia DMA a istruzioni CPU originali e non si modifica retroattivamente il significato delle precedenti prove prive di DMA. Il cambio frame aB2D50 resta astratto e la consegna dei dispatcher èCABI, non un IRQ elettrico.

## Esiti e correzione del contratto write

| Caso | Stato12DE3C | Conteggio | File-error subito dopo write | Close callback |
|---|---:|---:|---:|---:|
| r+ esistente | 0 |1024/1024|0|0|
| Nuovo esclusivoPIO |0|1024/1024|0|0|
| Nuovo con coda non intera |0|513/513|0|0|
| PIO errore bit2 o bit3 dopo256byte |0|0/1024|0|0|
| Timeout comando o errore completamento |0|0/1024|0|0|
| Cache record mancante |0|1024/1024|01A00006|0|
| Errore comando durante close directory |0|1024/1024|0|E00100|
| Nuovo asincrono |0|1024/1024|0|0|
| Async timeout o status bit2 |0|0/1024|0|0|
| Frammentato, errore dal secondo cluster |0|1024/2048|0|0|

La precedente affermazione che12DE3C restituisse zero soltanto sul conteggio completo è ritirata nel [binding ABI](S33_Dumper_RAM_Binding_SD_ABI.md):

1. Su conteggio completo,12DEE6 sceglie0 e non consulta file+0xC. Il caso cache assente produce1A00006 in1F337C dopo il trasferimento, e il conteggio pieno lo nasconde al chiamante superiore.
2. Su conteggio diverso,12DEEA legge file+0xC. Nel profilo con cache attiva, un successo successivo di1F337C può sostituire l'errore precedente:21A9DE aggiorna lo slot locale,21AA30 lo copia nel file-error. Sono osservati0byte e1024su2048 con stato0/file-error0.
3. Il valore ritornato dal close è un altro canale. Il suo errore viene osservato anche quando i dati erano stati completamente emessi.

Per il futuro adapter occorrono conteggio, stato, errore del file e close distinti. `ram_dump.h` richiede avanzamento positivo e il motore C gestisce scritture corte; l'adapter non può ridurre tutto a «r0==0». Questo banco non ha ancora aggiunto l'adapter Nikon al C.

## Errori, tentativi e danno strutturale atteso

Gli errori persistenti attraversano anche la logica superiore2A0D70: sono osservate nove chiamate motore, non tre per l'intera operazione. Il limite tre del solo168410 resta valido. Nei negativi iniziali la traccia mostra sei tentativi suLBA102 e tre su106. Le copie PIO possono precedere l'errore; il conteggio software0 non significa scheda invariata.

Nel caso asincrono timeout ci sono81ritorni timeout originali e8100tick del profilo1000/1000:9controlli stagnanti per ciascuna delle9chiamate motore. Non è una misura di millisecondi hardware. Il modello non copia dati write durante questi timeout.

Nel caso frammentato la FAT iniziale è2→4→FFF. Il primo cluster è scritto, gli errori interessano il secondo e i tentativi di sostituzione. L'API dichiara1024byte; la rilettura con contesto nuovo mostra1280byte del pattern e il restoCC. La FAT risultante resta2→4, ma la voce finale di4 èFF7. Il reader originale può soddisfare la dimensione senza validare un ulteriore link; questo non rende sana la catena.

Il parser host indipendente ricostruisce i contenuti dalle immagini e richiedeEOF per tutti gli altri casi; **asserisceFF7 soltanto per questo negativo**. `fsck.fat4.2 -n` lo respinge con`next_cluster on bad cluster`/exit1. I quattro positivi r+, nuovoPIO, nuovo513byte e nuovoasync hanno exit0. Gli hash prima/dopo dimostrano chefsck non cambia le immagini. Non si presenta la corruzione come comportamento hardware osservato o come errore innocuo.

## Fixture e copertura ancora aperta

Restano modellati: stato iniziale kernel/volume/dispositivi/geometria, heap/pool/free inferiori, clock21B300/21B2CC, servizio2A29B4, controllo3, cache17FAA4, delay2E500C, recovery25B63C e query25BF3C, prodotti DSP, DMA e registri/risposte hardware. Le funzioni filesystem, la guardia duplicato, FAT, copie PIO e servizi RTOS elencati sopra vengono eseguiti; i loro risultati non sono scritti direttamente dal test.

Il **primo raccordo superiore mancante** è il registro/apertura generica1F21F8 e il ciclo12DBFC/12D604 con slot del volume e proprietà del wrapper. Qui sono eseguite le callback1F43AC/1F48A4 su wrapper predisposti: il close consuma l'oggetto privato, ma può lasciare vecchio wrapper+4. Non va associato direttamente al contratto close-consumes del dumper. Restano backend7, w/w+/x, più nomi e directory, errori allocazione/sync integrati, concorrenza e guardia atomica dell'adapter.

## Stime separate e audit dell'obiettivo

Stesso criterio del checkpoint precedente: tappe offline a peso uguale, conteggiate soltanto quando provate nel profilo dichiarato. Non sono percentuali di firmware funzionante o sicurezza d'installazione.

| Area | Stima | Tappe |
|---|---:|---|
| Filesystem |75% (6/8)| lookup/apertura esistente, lifetime/lock, creazione, collisione, write-file, riapertura/contenuto provati; sync/close superiore completo e insieme completo degli errori ancora parziali |
| Write SD |75% (6/8)| tappe precedenti confermate; DMA ora modellata, ma cache e recovery/query originali restano da eseguire |
| Interrupt/eventi |63% (5/8)| register/router/dispatcher/eventi/risorse originali; frameCPU, IRQ fisico e interleaving non dimostrati |
| Adapter AkeruOS |20% (1/5)| contratto generico verificato; nessun nuovo adapter concreto prima di risolvere proprietà e backend |
| Hardware |0% (0/5)| compatibilità, residenza/stack, mappaRAM completa, recupero e acquisizione reale non provati |

| Requisito dell'allegato42b56cc8 | Evidenza attuale |
|---|---|
| SD FAT sintetica | BPB/FAT12 coerenti,110settori; contesto predisposto, mount originale assente |
| Creare/scrivere/chiudere/riaprire | Eseguiti nel banco;12DE3C e callback lifecycle originali, registro generico/slot superiori da raccordare |
| Byte/dimensioni/integrità | Confronto CPU con contesto nuovo, parser indipendente13immagini,fsck4positivi e1negativo strutturale atteso |
| Collisione senza overwrite |3casi nuovi, lookup/guardia originali, tutti i settori invariati |
| Errori/timeout/scritture corte |13scenari,81timeout e un conteggio positivo corto; copertura limitata ai fault dichiarati |
| Modi/backend7 | Rami statici e precedenti prove parziali; backend7 non eseguito qui |
| Adapter compatibile | Contratto disponibile; implementazione concreta ancora mancante |
| Requisiti primo dump reale | MappaRAM, memoria privata/task/hook, immagine compatibile e recupero restano necessari |

Il banco end-to-end del file ora esiste; **l'intero obiettivo resta attivo** per il raccordo lifecycle superiore, i modi/backend richiesti e l'adapter. Non sostituire tale obiettivo con la sola prova positiva del file né con i13PASS.

## Diagnostica conservata

Le prime iterazioni hanno fermato il modello per indice partizione mancante e campo SD+D4 sconosciuto. Una preparazione senza buffer della cache record ha poi rivelato il conteggio pieno con errore1A00006, divenuto un negativo dedicato. Il primo controllo host richiedevaEOF anche al negativo frammentato: l'ispezione ha identificatoFF7 e il test è stato corretto per **rilevare** quel danno, conservando il rifiuto diEOF errato negli altri casi. Rimossi labelBPB senza entry volume e un'etichetta di traccia che chiamava write tutti i trasferimenti2A0D70. Nessuna modifica al decoder o al firmware per superare i controlli.

## Continuazione — registro, close superiore e modi,23ottobre2026

[17casi lifecycle](S33_Dumper_RAM_SD_Registro_Apertura_Close_e_Ownership_Integrati.md) eseguono ora anche registro/open generico/open eclose superiori. L’errore prima3015 conserva handle/slot/oggetto perretry;ready0consuma wrapper/slot/cella ma lascia oggettoFAT vivo. Non associare cella0 a cleanup completo. 4fsckpositivi e7negativiFF7attesi,regressione13PASS. [20casi modi](S33_Dumper_RAM_SD_Modi_Apertura_FAT_e_Gate_Backend7.md) verificano w/w+,n/n+,r/r+,x/x+ sulFAT;backend7 solo gatechiuso. Il nuovo confine è backend7 attivo e adapter con proprietà/guardia/sessione verificati;nessun bindinghardware,C/GNU/originali invariati,NON_INSTALLARE.
