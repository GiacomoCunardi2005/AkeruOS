# Dumper RAM: ABI originale SD e creazione di nomi temporanei

22 ottobre 2026. Analisi offline V1.1, byte originali verificati; nessun dispositivo eseguito. Non è ancora un binding pronto per installazione.

## Percorso completo già presente nel firmware

`0x30017C(path, buffer, length, &written)` è un wrapper di esportazione originale. Conserva gli argomenti r0/r1/r2/r3, chiama `0x12DBFC(path,2,&file)` a `0x30019A`, poi `0x12DE3C(file,buffer,length,0,&written)` a `0x3001B2`, infine `0x12D604(&file)` a `0x3001BC`. Restituisce stato open/write conservato in r13: **il close non è propagato**. Non usarlo come prova di persistenza o come creazione esclusiva: mode2 seleziona `w+`.

| Servizio | ABI verificata |
|---|---|
| `0x12DBFC` | r0 path, r1 mode, r2 &file; r0 stato (zero successo), puntatore scritto all'uscita |
| `0x12CE8C` | apertura lettura; r0 path, r1 selettore `0x11`→`r`, altrimenti `r+`, r2 &file |
| `0x12DE3C` | r0 file, r1 buffer, r2 byte richiesti, r3 selettore (originale dump passa0), r4 &byte scritti; r0 stato |
| `0x12D604` | r0 &file; r0 stato; può azzerare la cella anche con close fallito |
| `0x1F21F8` | r0 path, r1 stringa modo; restituisce puntatore file o zero; passa dal callback dispositivo+0xC |
| `0x1FA090` | r0 file, r1 buffer, r2 byte; r0 conteggio; callback dispositivo+0x18 |

Il write superiore non va trattato come POSIX `write`: conserva il conteggio in `*r4` a `0x12DECC` e confronta il totale con r17 a `0x12DEE2`. **Correzione del23ottobre, prove integrate:** sul conteggio completo sceglie zero senza consultare file+0xC; su conteggio diverso legge quel campo, che può già essere stato azzerato da un servizio successivo. Sono quindi osservati anche stato0/conteggio0 e stato0/1024su2048, oltre a conteggio pieno con file-error1A00006. La precedente formulazione «zero soltanto sul conteggio completo» è ritirata. [Catena file e confini](S33_Dumper_RAM_SD_File_FAT_Creazione_Scrittura_Close_e_Riapertura.md). Le sincronizzazioni originali non certificano persistenza e non dispensano dal verificare conteggio, errore del file e close.

## Modalità: n non è una prova di esclusività

Raw string a `0x3668DE`: `w\0w+\0n\0n+\0`. La selezione `0x12DC80..9C` è 1→w, 2→w+, 3→n, qualsiasi altro valore→n+.

Le tabelle originali del parser `0x1F43AC` sono state lette come byte signed e ricalcolate con base+offset×2, evitando il disassemblaggio dei dati come istruzioni:

| Modo | Backend contesto+0x70==7 | Backend contesto+0x70!=7 |
|---|---|---|
| r | `0x1F44B8` | `0x1F4586` |
| w | `0x1F44D8` | `0x1F45A4` |
| n | **stesso ramo w** | `0x1F45FC` |
| x | `0x1F449A` | `0x1F4574` |

Nel backend diverso da7 n invoca `0x2A1648`, w invoca `0x2A13F8`. L'esclusività di n non è dimostrata, e nel backend7 non è distinguibile da w. **Non associare `open_new` a mode3 sulla sola base del nome n.**

## Alternativa originale x: nomi TMP autonomi

Il parser riconosce x, ma la semantica osservata non è C11 `fopen(path,"x")`:

- il path è una directory, per esempio `B:\\`, non il nome finale AKR00000.DMP;
- backend !=7: `0x1F4574 → 0x2A16F0`; alloca un buffer261byte, risolve il contesto con `0x2A1300`, genera nomi tramite `0x12CE54`;
- formati raw `0x36C444/0x36C455`: `%sTMP%05.5lu.@@@` oppure `%s\\TMP%05.5lu.@@@`, scelti a seconda del separatore finale;
- numero iniziale0, budget300, numero incrementato a `0x2A17CE`; ripete soltanto se stato `0x01A00011` (`0x2A17D0..F8`);
- successo: alloca il contesto file e copia nome generato, incluso NUL, a **contesto file+0x44** (`0x2A1810..1E`); il buffer input del chiamante non viene modificato;
- backend7 ha helper `0x1F4258`, stesso formato a `0x3693B8/0x3693C9`, budget300;
- il wrapper `0x12DBFC` non offre selettore x: per usarlo occorre il generico `0x1F21F8(directory,"x")` e una gestione coerente con la tabella file del volume.

Questo offre una pista concreta per nomi nuovi scelti dal firmware, ma **non prova ancora l'atomicità fail-if-exists**. L'helper `0x2AC2B4` chiama `0x2ABCD4`, tratta diversamente errori/puntatori secondo il settimo argomento e viene invocato da x con r6=0. Prima del binding occorre dimostrare, attraverso quel livello, che una collisione non modifica il file precedente; il solo retry di un codice non basta. Va inoltre verificato se bypassare la tabella60 slot è compatibile col close superiore: non combinare open generico con close superiore senza raccordo.

## Evidenza riproducibile

`python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_abi.py`: PASS16 hash, roundtrip payload0,13 finestre,15 istruzioni asserite,2 tabelle di modalità,4 stringhe formato. [JSON](../Risultati/Runtime_Kernel/RAM_Dumper_SD_ABI/verified_evidence.json), [listato GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_ABI/gnu_verified.txt). Non modifica GNU, firmware né indici. Le altre finestre esplorative nella stessa cartella non sono parte del set di asserzioni.

Prossimo passo: verificare la collisione in `0x2AC2B4/0x2ABCD4` oppure costruire un wrapper originale superiore per x con registrazione slot e close coerente. Mappa RAM, task e memoria privata sono lavori separati. NON_INSTALLARE.

## Aggiornamento: guardia duplicato eseguita nella CPU originale

La prosecuzione ha isolato il significato del codice `0x01A00011`, evitando di inferirlo dal solo retry. In `0x2ABCD4`, se **contesto+190*4 == 0**, il primo lookup `0x2ABD20 → 0x2A2D88` riceve ancora il nome originale r1. Se trova un puntatore non nullo, `0x2ABD28..34` carica il pool `0x2AC078 = 0x01A00011` e torna col puntatore esistente: il ramo evita la creazione e gli aggiornamenti dell'entry. Se il lookup restituisce nullo, prosegue a `0x2ABD36`.

`0x2AC2B4` distingue poi l'uso di quel puntatore: `0x2AC3C8..D0` azzera il puntatore quando lo stato è nonzero e **r6 originario==0**; con r6==1 può conservarlo. Nel backend diverso da7, n e x passano0, w passa1. Questo dimostra la guardia **new-only condizionata** al backend e al campo contesto verificati; corregge la precedente ipotesi esplorativa secondo cui n fosse necessariamente open-existing. Il backend7 continua a condividere n/w, perciò il selettore3 non è universalmente sicuro.

Prova [CPU](../Python_Trace_Scripts/s33_run_ram_dump_sd_create.py), [Java](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDCreate.java), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_ABI/cpu_duplicate/trace.txt): **6 casi PASS nel P-code originale**. Due eseguono il vero prologo/guardia/ritorno di `0x2ABCD4`, sostituendo soltanto la directory lookup; quattro eseguono `0x2AC2B4`, con fixture per allocatore, parsing e servizio create. Verificati puntatore rifiutato/accettato secondo flag, stato11 conservato e campo dimensione dell'entry invariato. Il caso assente della guardia si ferma alla continuazione prima della creazione: **non è una prova FAT completa né SD reale**.

Per un binding concreto senza TMP, la pista migliore è ora `0x12DBFC(path,3,&file)` **con rifiuto esplicito dei backend non dimostrati**. Da un file di sola lettura sullo stesso volume: `[file]` è dispositivo, `[device+0x24]` è contesto filesystem; `context+0x70` deve essere diverso7. La funzione n carica `[context+106*4]` (handle inferiore) e `0x2A1300` ne risolve il contesto finale tramite `[handle]→[device+0x24]`; il campo finale +190*4 deve essere0. La validazione deve essere raccordata alla sincronizzazione originale, non resa una check/create separata senza lock. `0x2A1300` prende il mutex `contesto+388` tramite `0x23ECA4`, e `0x2A1398` lo rilascia con `0x23EE48`: è il mutex originale che protegge il percorso n. La prova della stabilità dei campi tra preflight e open resta necessaria prima dell'attivazione hardware.


## Continuazione — proprietà degli handle sui rami di errore, 23 ottobre 2026

La [nuova verifica CPU](S33_Dumper_RAM_SD_Handle_Errori_e_Chiusura.md) esegue25casi: open può pubblicare handle e slot prima di un errore unlock; close può conservare entrambi su errore ioctl3015, ma li azzera dopo1F22C0 anche se questo fallisce. Tre casi separati del close generico verificano richiesta di free anche con errore callback. Il contratto astratto close-consumes richiede quindi un adattatore, non il solo inoltro diretto. La stabilità del backend e l’atomicità new-only restano aperte.

## Continuazione — semaforo e inizializzazione, 23 ottobre 2026

[22 casi successivi](S33_Dumper_RAM_SD_Semaforo_Campo_Temporaneo_e_Inizializzazione.md) provano azzeramento iniziale852 byte, campo760/backend+0x70 a0 e semaforo+388 iniziale1. Il campo temporaneo di d è ripristinato prima del post; n non normalizza un valore1 già presente. La primitiva è un semaforo a conteggio: seconda wait nello stesso task si accoda. Non pre-acquisirlo per chiamare un open che lo acquisisce nuovamente. Restano scrittori successivi/backend e mount/unmount; nessuna integrazione hardware, NON_INSTALLARE.

## Continuazione — montaggio e chiusura, 23 ottobre 2026

[16 nuovi casi](S33_Dumper_RAM_SD_Mount_Chiusura_e_Stabilita_Backend.md) eseguono mount1F3EF0 e callback close1F48A4/ramo volume1F46C4. La scelta backend è sotto semaforo ma+424 è pubblicato prima; una query fallita salta il post nel modello. Close backend7 azzera+424 dopo il post, backend1 riacquisisce e controlla la halfword+108. Restano lifetime e livello superiore di sincronizzazione; non è prova di race/deadlock hardware. Prossimo: scrittori+108 e chiamanti close. NON_INSTALLARE.

## Continuazione — oggetti file e guardia, 23 ottobre 2026

[Sei sequenze successive](S33_Dumper_RAM_SD_Lista_File_e_Guardia_Chiusura_Volume.md) attribuiscono context+108 al conteggio della lista file a+100 nel backend1. Open n e close ordinario originali incrementano/decrementano; volume close e ingresso225A60 rifiutano con oggetti vivi. Due ordini di rilascio e fallimenti pool/collisione verificati. Non è ancora prova di r/open-existing, di altri backend o di tutti i mutatori. Prossimo: handle di appoggio in sola lettura e sincronizzazione superiore. NON_INSTALLARE.

## Continuazione — riferimento di lettura, 23 ottobre 2026

[12 casi successivi](S33_Dumper_RAM_SD_Handle_Lettura_e_Protezione_Volume.md) seguono r/r+ fino a lookup fixture2A3360 e lista oggetti originale. r non chiama create, modo0 mantiene la guardia volume; un caso conserva r durante n su nome diverso. Attributi, errori e flagcontext+720 verificati. Non è prova fisica di file esistente o assenza di ogni scrittura filesystem. Prossimo: corpo lookup e altri scrittori/backend; NON_INSTALLARE.

## Continuazione — coordinatore lookup originale, 23 ottobre 2026

[18 casi successivi](S33_Dumper_RAM_SD_Lookup_Parser_Errori_e_Buffer.md) eseguono2A3360 e parser con due livelli inferiori ancora fixture. Il fallimento alloc257 del parser non viene propagato: nel profilo0 finisce01A00002.259A58 non ha l'azzeramento di268EE4; profili heap0/A5 dichiarati. Non trasferire automaticamente le proprietà al test r precedente: integrazione ancora da fare. Prossimo2A318C/2A2D88; NON_INSTALLARE.

## Continuazione — walker e scanner originali, 23 ottobre 2026

[Nuova verifica](S33_Dumper_RAM_SD_Directory_e_Scanner_Record_Originali.md):20casi con2A318C originale nel coordinatore,8separati dello scanner2A2D88 su settore sintetico,18regressione. Errori directory e allocnull diventano01A00003; al marcatore0 lo scanner può conservare lo stato ricevuto. Non sono ancora una catena integrata né I/O fisico; prossimo albero di settori sintetici e raccordor. NON_INSTALLARE.

## Continuazione prioritaria — identità del record, 23 ottobre 2026

[20lookup integrati+7r/close](S33_Dumper_RAM_SD_Lookup_Integrato_e_Falso_Successo_Parser.md) riproducono un falso successo con alloc257 parser nulla e scratch0: il finder originale restituisce il record vuoto e r lo registra. Confermato anche con errore inferiore nonzero conservato nel task. La semplice presenza di un handle vivo non prova che corrisponda al file richiesto. Cache/settori/heap inferiori fixture, nessun create o BIN modificato. NON_INSTALLARE.

## Continuazione — r/FAT/PMSD/DEVSD/close integrati

[S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md](S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md):22casi contratto conteggi/flag e13matrici r/FAT/close ora attraversano PMSD, DEVSD e adattatore SD originale, con2015/16 e semafori. Count raw intero/0 ed errore copiato; flag49=1 può riportare successo senza aggiornare buffer. Separazione FAT/r superata; motori dati e runtime flag restano aperti. Nessun hardware, GNU o BIN modificato.

## Continuazione — motori read e PIO eseguiti

[S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md):20PIO,28motori,13r/FAT/PMSD/SD/PIO/close. Il confine prima degli interi B15B4/B16D0 è superato: preparazione,descrittori,copia CPU/MMIO e completamento ora eseguiti. Dispatcher comandi2E52F4 e25AA8C restano fixture;profili sintetici,non prova elettrica. Percorso write/asincrono non generalizzato dal read. Nessun hardware o BIN modificato.

## Continuazione — dispatcher e gate originali eseguiti

[S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md](S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md):40casi isolati e16scenari r/FAT/PMSD/SD/comandi/PIO/close;2E52F4 e25AA8C non sono più fixture nel nuovo profilo. Provati timeout8000 e limiti gate2000, risposta dalla porta originale, tipo0 che scarta errore e resetcountalto fisso0FF01854. Errori comando/risposta dati propagati dopo3tentativi, erroreFAT ancora trasformato in02. Quattro regressioni13casi PASS. Le prove precedenti mantengono il proprio confine; nientehardware. Prossimo25A83C/2801F0 asincrono e lifetime buffer, produttoreflag49. NON_INSTALLARE.

## Continuazione — chiamante read asincrono

[S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md](S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md):21scenari del corpo25A83C,servizi inferiori/eventi fixture. Verificati30controlli consecutivi senza progresso,uscite parziali dopo acquisizione e precedenza degli errori cleanup. Non trasferisce dati e non amplia il profilo filesystem integrato. Prossimo2801F0/27FCD4,28080C/281158,ownership ecallback/eventi originali. NON_INSTALLARE,nessunhardware.

## Continuazione — oggetti di ricezione originali

[S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md](S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md):18casi2801F0/27FCD4/281158/281064 e21caller25A83C collegati all'oggetto512CC8,regressione21PASS. Tre oggetti receive512CC8/512CEC/512D10 distinti dai precedenti oggetti write512C5C/512C80/512CA4;release consumaid+4 ehandle anche con errorepost. Le releasefixture precedenti non descrivono questo contratto reale. Earlycallback-error lasciarecord nonripulito,senza prova di leakglobale o avviofisico. Avvio28080C/progress266E9C,semafori/eventi e hookstop restano daeseguire. NON_INSTALLARE,nessunhardware.

## Continuazione — avvio receive e notifica originali

[S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md](S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md):33casi28080C/programmazione/MMIOdispatcher/callback e266E9C. Slotread36B358/35C/360 ecallbackADBC/ADC4→E00005/40o40000,distinti dal percorso write storico. Il bytefine del servizio avvio è calcolato prima della callback;getterprogress halfword×128nonvalidaownership. Evento158CBC ancora recorder e ingresso dispatcher esplicito; nessuntrasferimento fisico. Prossimo raccordare25A83C/oggetti/start/progress/callback/release e servizi evento originali. NON_INSTALLARE.

## Continuazione — catena con eventi RTOS originali

[S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md](S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md):13scenari25A83C/oggetti/start/dispatcher/callback/SET/WAIT/query/CLEAR/release,10ritorni+3waitaccodati osservati prima2313AC. Eventoeffettivo373228,tabellastaticabase372A48;auto-clear1spiega querysenza completion dopowait riuscito. EndByte1puòcoesisterecon task1069ancora inwait. Progressgetter nonraggiunto daquestiprofili:prossimo deadline/scheduler/timeout e callbackstatus reali;notificaCABIinnestata,nonIRQfisico. NON_INSTALLARE.

## Continuazione — scadenza, errori e inizializzazione SD originali

[Scadenza e risveglio](S33_Dumper_RAM_SD_Scadenza_Risveglio_e_Progress_Originali.md):2313AC/28179C e tick2F70C4 portano il task fuori dalle liste e permettono il ritorno del WAIT originale fino a266E9C. Regressione8scenari,136timeout/136progress;B2D50 resta un confine astratto prima del frameCPU.

[Callback di stato](S33_Dumper_RAM_SD_Callback_Stato_Errori_e_Inizializzazione.md):28nuovi casi eseguono anche266768/26671C/2667B0,router040E,walker2640E0 e25AD3C/25AD78 fino aE01520/E01620,release e ripristino maschera.158C30 sul recordSD statico flags2 seleziona auto-clear0 e pubblica il gate. I negativi flags3 nascondono l'errore prima della query;il gate framework0 causa errore200604 con effetti parziali conservati. Questi rami non sono più fixture nel nuovo profilo. Il percorso write del dumper,la mappa fisica e il binding compatibile restano necessari;nessunhardware o BIN,NON_INSTALLARE.

## Continuazione — prenotazione reale e write originale

[Risorse](S33_Dumper_RAM_SD_Arbitraggio_Risorse_e_Stop_Software_Originali.md):34casi eseguono try-acquire/post/attesa/helper originali;1594E4 decrementa il token e scrive1byte. [Write](S33_Dumper_RAM_SD_Scrittura_Asincrona_e_PIO_Originali.md):36casi3040DC/oggetto512C5C/risorsa1E00000/start/dispatcher2689FC/eventi/status/timeout/release e copiePIO,con9216byte catturati da storeMMIO originali. È avanzamento verso la scrittura del dumper,non un binding filesystem completo né SDfisica. Prossimo raccordo PMSD/DEVSD/write/creazioneesclusiva/close;restano mappafisica e task/hookcompatibile. NON_INSTALLARE.

## Continuazione — motori write e rilettura,23ottobre2026

[Nuovo collegamento](S33_Dumper_RAM_SD_Motori_Write_PMSD_e_Rilettura.md):24casi eseguono PMSD/DEVSD e motori25B9C0/25BB5C con comandi/gate/PIO originali;13riletture/11264byte,15catture12800byte,regressione36PASS. Errori dopo256byte pertre tentativi diventano raw/PMcount0;flag49=1 conserva falso successo senzaemissione. La scheda è una finestraRAM,nonFAT;async senza copiaDMA dichiarata. Il callback filesystem1F4958/21A4B8 ecluster2A0D70 restano da integrare,poi creazione/sync/close/riapertura. Stime perarea nelrapporto,obiettivoattivo,Cinvariato,NON_INSTALLARE.

## Continuazione — fileFAT e correzione write,23ottobre2026

[13nuovi scenari](S33_Dumper_RAM_SD_File_FAT_Creazione_Scrittura_Close_e_Riapertura.md) eseguono creazione n/collisione,allocazioneFAT,12DE3C→PMSD/DEVSD/controller,close e riapertura con contesto nuovo.4immagini positive superanofsck;il negativo frammentatoFF7 viene respinto. Stato0puòaccompagnarecount0 o1024/2048 ecountpienopuònasconderefileError1A00006. HardwareDMA esplicitamente modellata,81timeout/8100tick,regressione24PASS. Ilprimo confine superiore èora1F21F8/12DBFC/12D604 conregistro/slot/ownership,poibackend7/modi eadapter. C eGNU invariati,mappafisica/task/hookancoranecessari,obiettivoattivo,NON_INSTALLARE.

## Continuazione — registro, close superiore e modi,23ottobre2026

[17casi lifecycle](S33_Dumper_RAM_SD_Registro_Apertura_Close_e_Ownership_Integrati.md) eseguono ora anche registro/open generico/open eclose superiori. L’errore prima3015 conserva handle/slot/oggetto perretry;ready0consuma wrapper/slot/cella ma lascia oggettoFAT vivo. Non associare cella0 a cleanup completo. 4fsckpositivi e7negativiFF7attesi,regressione13PASS. [20casi modi](S33_Dumper_RAM_SD_Modi_Apertura_FAT_e_Gate_Backend7.md) verificano w/w+,n/n+,r/r+,x/x+ sulFAT;backend7 solo gatechiuso. Il nuovo confine è backend7 attivo e adapter con proprietà/guardia/sessione verificati;nessun bindinghardware,C/GNU/originali invariati,NON_INSTALLARE.
