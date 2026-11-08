# S33 — ingresso del servizio di acquisizione

Analisi statica del 17 ottobre 2026. Obiettivo: trovare il confine che una futura interfaccia essenziale potrà usare per richiedere l'acquisizione, conservando la gestione originale dei task e dei buffer.

## Correzione di ambito del percorso precedente

Il descrittore a `0x372908` contiene ID `0x40100005`, entry `0x1637bc` e nome **Take still inside Video**. È il task che portava al chiamante `0x163886 → 0x127b60` del rapporto sul salvataggio.

La catena documentata resta valida, ma il suo ingresso è attribuibile alla foto durante il video. Non dimostra l'ingresso della fotografia normale. La nuova verifica collega nome, descrittore e codice attraverso i byte originali del blocco 01.

## Servizio centrale CapMgr

La funzione `0x14aa24` presenta questo contratto candidato, ricostruito dall'uso dei registri:

```text
r0 = puntatore a funzione
r1 = puntatore ai dati della richiesta, obbligatoriamente non nullo
ritorno r0 = errore di servizio oppure risultato della funzione eseguita
```

È una descrizione per l'analisi, non un prototipo C validato. Mancano ABI completa, vincoli sul contenuto dei dati e regole di concorrenza.

| Passaggio | Evidenza osservata |
|---|---|
| Protezione | Acquisisce il servizio di sincronizzazione `0x1593ac` sull'identificatore `0x500003` |
| Richiesta | Nel contesto `0x366fa0` scrive funzione a +`0x24`, dati a +`0x34`, valore iniziale del risultato a +`0x38` |
| Cambio stato | Può invocare una callback di transizione se lo stato precedente è 2, 3 o 5; poi imposta lo stato 7 a +`0x2c` |
| Segnalazione | Cancella il bit `0x20` e imposta il bit `1` sull'evento `0x500004` |
| Attesa | Attende `0x20` e, se l'attesa restituisce zero, legge il risultato a +`0x38` |
| Uscita | Rilascia la sincronizzazione tramite `0x1594a4` e propaga l'errore o il risultato |

Il task **CapMgrTask**, entry `0x14a4c4`, attende il bit `1` sullo stesso evento. La tabella di salti usa byte signed: per lo stato 7 conduce a `0x14a5a8`. In quel ramo il task carica la funzione da contesto +`0x24`, la chiama con il puntatore a +`0x34` come primo argomento e salva il ritorno a +`0x38`. Infine imposta `0x20`.

Il significato di funzione e dati è così verificato da entrambi i lati del passaggio fra task. Questo permette di individuare un confine più preciso rispetto a chiamare direttamente una routine profonda del sensore.

## Chi richiede l'acquisizione

Il percorso a `0x1b8f24` seleziona una callback e chiama `0x14aa24` a `0x1b9198`. Nei rami esaminati compaiono le callback `0x1ba9c4`, `0x1bbd38` e `0x1bb2b4`, caricate tramite indirizzamento PC relativo scalato. I dati passati provengono dalla prima parola della struttura ricevuta dal chiamante.

Esiste una seconda chiamata al servizio a `0x1b9276`, dopo ulteriore selezione di callback e aggiornamento dei dati. Non abbiamo assegnato un nome utente a queste varianti. Non è giustificato eliminarne una perché sembra un'opzione secondaria: possono rappresentare configurazioni o fasi necessarie.

`0x1b9ea8` conserva gli argomenti, attende un servizio precedente e richiama `0x1b8f24` a `0x1b9f1e`. Altri riferimenti diretti a `0x1b8f24` sono presenti nelle regioni `0x183a54`, `0x1b9dd0` e `0x1dca94`; il loro ruolo di modalità normale, speciale o diagnostica resta da attribuire. Le ricerche nel disassemblaggio lineare sono piste e non una ricostruzione esaustiva di tutti i chiamanti indiretti.

## Decisione per la base essenziale

Conservare **CapMgrTask, sincronizzazione e transizioni di stato**. La futura applicazione dovrà preparare una richiesta valida e servirsi del confine originale; non esiste ancora una richiesta minima completa da inviare. Il comando fisico S2, le condizioni di messa a fuoco/esposizione e il collegamento dalla callback selezionata al lavoro JPEG restano da seguire.

Non c'è ancora evidenza che rimuovere la grafica riduca il tempo di acquisizione. La sincronizzazione individuata offre però punti precisi in cui misurare in seguito tempo di attesa, esecuzione del sensore ed elaborazione.

## Continuazione: dati necessari prima di chiamare CapMgr

La routine `0x1b8f24` svolge preparazione sostanziale prima di `0x14aa24`. Non basta passare a CapMgr un puntatore arbitrario o una struttura azzerata.

| Argomento di `0x1b8f24` | Uso osservato, significato ancora parziale |
|---|---|
| `r0` | Indirizzo di una cella dove viene scritto il puntatore al descrittore; dopo la preparazione il codice legge ripetutamente `*r0` |
| `r1` | Discriminante: viene conservato sullo stack e il byte basso viene scritto nello stato condiviso `0x368790 + 2`; diversi valori selezionano percorsi distinti |
| `r2` | Viene passato come primo argomento al servizio di preparazione `0x18ed60` |
| `r3` | Se non nullo, viene passato al servizio `0x1378b4` insieme al campo +`0x48` del descrittore; contenuto e formato non ancora risolti |
| `r4` | Parola scritta a stato condiviso +`4` |
| `r5`, `r6` | Memorizzati come mezze parole a stato condiviso +`8` e +`0xa` |

Nel ramo ordinario rispetto alla distinzione interna `r1 == 0x10`, la routine chiama `0x18ed60(r2, r0_originale, 0)`. Se il servizio segnala errore o la cella del descrittore risulta nulla, evita di raggiungere CapMgr. La parola «ordinario» qui distingue due rami di codice: non identifica ancora la modalità fotografica dell'utente.

Nel ramo riuscito di `0x18ed60`, il descrittore viene restituito attraverso la cella ricevuta; il codice popola almeno i campi +`4`, +`8` e +`0xc`. Se il primo argomento non è nullo, uno dei percorsi calcola il valore per +`4` come argomento +`0x5000`; gli stati interni `0xe` e `0xf` usano invece un valore letto a argomento +`4`. Con argomento nullo il codice segue un percorso diverso, con acquisizione di risorse e verifiche di stato. Questi comportamenti impediscono di fissare già una disposizione universale del buffer.

Successivamente `0x1b8f24` richiama `0x1ba558` con il descrittore e altri parametri prima di selezionare la callback per CapMgr. La firma completa di questo preparatore è il prossimo nodo da risolvere, insieme alla durata delle risorse restituite. Il ritorno finale di `0x1b8f24` proviene dalla parola di stato locale a frame -`188`.

## Etichette diagnostiche collegate al codice

`0xbcff0` passa la base `0x370950` e il conteggio 73 a `0x12ca94`, che li registra nel contesto `0x3668b4`. Nel ramo per eventi personalizzati, `0x12cd60–0x12cd90` ricava l'indice sottraendo `0xb80000` e risolve il puntatore alla stringa nella tabella registrata. È stata verificata la corrispondenza seguente:

| Codice | Testo originale |
|---|---|
| `0xb80021` | S2 ISR CallBack |
| `0xb80022` | Recorder Capture Image Start |
| `0xb80023` | Recorder Capture Image End |
| `0xb80024` | CapMgr_TakeImg Start |
| `0xb80025` | CapMgr_TakeImg End |

A `0x1b9188` il codice carica `0xb80024`, lo passa al registratore `0x12cad4` e poi chiama CapMgr a `0x1b9198`. Nel ramo di successo compare `0xb80025` a `0x1b91be–0x1b91c2`. Questo corrobora l'attribuzione della chiamata all'acquisizione. L'effettiva esecuzione della registrazione iniziale e dei marcatori sulla macchina non è stata osservata.

**Il marcatore S2 è ancora solo una voce della tabella:** non è stata identificata la routine del pulsante che lo emette. Una ricerca dei puntatori uint32 ai due ingressi `0x1b9ea8` e `0x1b8f24`, nei 16 blocchi TBM e nelle due rappresentazioni LE/ARC esaminate, non ha trovato occorrenze; questo non esclude chiamate dirette relative, puntatori calcolati o copie. Le chiamate relative già documentate rimangono valide.

### Continuazione: correlatore del blocco 02

Nel blocco 02, il tratto `0x65F230–0x65F268` invoca il registratore `0x12CAD4` con il marcatore `0xB80022` nel delay slot, chiama `0x1B9EA8`, quindi invoca lo stesso registratore con `0xB80023`. I testi registrati sono rispettivamente **Recorder Capture Image Start** e **Recorder Capture Image End**. Il tratto appartiene all'handler `0x65ED6C..0x65F45A`, registrato nel blocco 03 con la stringa **CaptureImage**. Il ramo è selezionato quando il byte di contesto `0x681FF0 + 0x1D` vale `0x0A`; il suo significato resta sconosciuto. Questo collega in modo statico il perimetro della cattura a un ingresso CapMgr, ma non identifica ancora la sorgente S2 del ramo.

Le richieste JPEG del blocco 04 sono state tracciate separatamente: [blocco 04 e confine S2](S33_Blocco04_Origine_Scatto.md). Nessuna delle tre funzioni analizzate è stata attribuita alla foto normale, al video o all'anteprima.

## Continuazione: disposizione della memoria della richiesta

È stata seguita la routine di preparazione `0x1ba558` fino al ritorno. Essa riceve il descrittore in `r0`, legge impostazioni attraverso vari servizi e popola sia la parte iniziale sia aree accessibili tramite puntatori interni. Il chiamante a `0x1b90ee` imposta `r5 = 1`; ciò abilita il ramo di costruzione delle aree aggiuntive.

La parte iniziale contiene il valore `0x30` come mezza parola a +`0` e **444 (`0x1bc`)** a +`2`. Quest'ultimo valore è un candidato campo di dimensione della parte primaria: **non rappresenta tutta la memoria richiesta dal preparatore**.

Nel ramo `r5 != 0`, `0x1ba758–0x1ba7e4`:

- azzera `[base + 0x1bc, base + 0x4d50)`: lunghezza `0x4b94` verificata dal letterale a `0x1ba818`;
- inizializza una serie di puntatori assoluti verso aree interne;
- azzera nuovamente `[base + 0x4aa8, base + 0x4d50)`, lunghezza 680 byte;
- invoca una callback opzionale di configurazione e aggiorna altri campi.

L'azzeramento è sostenuto dalla catena `0xad90c → 0x13a954`: il wrapper imposta a zero il valore da ripetere e passa la lunghezza; la destinazione implementa scritture di byte/parole.

| Campo del descrittore | Puntatore costruito, relativo alla base |
|---|---|
| +`0xa8` | +`0x41bc` |
| +`0xac` | +`0x425c` |
| +`0xb0` | +`0x471c` |
| +`0xb4` | +`0x4a2c` |
| +`0xb8` | +`0x47f0` |
| +`0xbc` | +`0x4808` |
| +`0xc0` | +`0x46f0` |
| +`0xc4` | +`0x4a5c` |
| +`0xcc` | +`0x4a34` |
| +`0xd8` | +`0x1bc` |
| +`0xdc` | +`0x4aa8` |

La routine ausiliaria `0x1ba820` arrotonda una quantità a multipli di quattro e rifiuta un avanzamento oltre `base + 0x5000`. Questo sostiene l'esistenza di un limite di area di lavoro di **20 KiB** in quel helper; non prova la dimensione di ogni allocazione effettiva. Le scritture osservate nel preparatore richiedono almeno `0x4d50` byte (19.792) per il ramo esaminato. Altre routine possono imporre ulteriori requisiti.

Anche dopo aver costruito questi puntatori, il preparatore chiama `0x1bbe14`. La finestra iniziale di quest'ultima routine legge il campo +`0xd8` e trasferisce impostazioni in offset profondi di quell'area. Non è stata ricostruita per intero; il solo elenco di puntatori non è quindi sufficiente per sostituire il preparatore.

### Provenienza di un descrittore

Nel ramo di preparazione con primo argomento nullo di `0x18ed60`, il codice passa da `0x18e8b4 → 0x277244 → 0x2e8aa8`. Quest'ultima routine controlla il conteggio di una coda, estrae un elemento dalla lista collegata e decrementa il conteggio. Il wrapper avanza di quattro byte il puntatore alla struttura della coda e segnala errore se non ottiene un elemento. La [continuazione sul ciclo delle risorse](S33_Descrittori_e_Ciclo_Buffer.md) distingue ora questo elemento dal descrittore, riservato separatamente tramite `0x18e204`: la tabella contiene puntatori costruiti in passi di `0x5000` byte, con stati 0/1/2. Non è un'allocazione generica tramite heap.

### Conseguenza per l'applicazione essenziale

La base da conservare comprende preparatore, risorse e durata del descrittore. Una struttura da 444 byte sarebbe insufficiente per il ramo verificato; una copia grezza del blocco manterrebbe puntatori verso la vecchia base. Una futura richiesta minima deve usare il preparatore originale con risorse valide e mantenere il descrittore vivo durante tutte le fasi che lo referenziano. Non è stata ancora determinata l'ultima fase che ne permette il rilascio.

## Continuazione: restituzione condizionale delle risorse

La routine `0x18ee50` consulta il contesto `0x368024`. Se il campo +`0x24` è nullo e l'elemento della coda dei buffer a +`0x1c` è presente, lo passa insieme alla struttura a +`4` alla catena `0x18e9d0 → 0x27722c → 0x2e8a54`; poi azzera il campo +`0x1c`. La [verifica successiva](S33_Descrittori_e_Ciclo_Buffer.md) attribuisce questo trasferimento alla coda B dei buffer acquisiti pendenti, distinta dalla coda A dei disponibili. Non rende libero il record del descrittore. Negli altri casi restituisce zero senza attraversare quella catena.

La routine `0x18e9d0` usa lo stesso identificatore di sincronizzazione `0x40100001` del percorso di acquisizione da coda `0x18e8b4`. Il wrapper `0x27722c` avanza il primo argomento di quattro byte, chiama `0x2e8a54` e traduce il ritorno 1 in zero. `0x2e8a54` aggiorna i collegamenti della lista, incrementa il conteggio a +`8` e può rifiutare l'inserimento se il limite a +`0xa` è già raggiunto. Queste operazioni corroborano l'interpretazione di restituzione alla coda delle risorse originali.

Il campo di contesto +`0x24` viene valorizzato dal percorso che riceve memoria dal chiamante in `0x18ed60`. La distinzione è coerente con proprietà diversa della memoria: risorsa interna restituita alla coda, memoria del chiamante esclusa da quel rilascio. È un'interpretazione sostenuta dalle scritture e dai rami, non una regola completa di proprietà già validata.

Nel tratto finale di `0x1b8f24`, la chiamata a `0x18ee50` è presente a `0x1b93b0`, saltata per i discriminanti `0x10`, `0x11` e `0x12`. Il ramo esaminato **non usa il suo ritorno per aggiornare lo stato locale restituito al chiamante**. Inoltre, i precedenti rami d'errore possono saltare direttamente all'epilogo `0x1b93bc`, evitando questo tratto. La presenza del rilascio nel finale non dimostra quindi che ogni percorso completi e liberi tutte le risorse.

È stata trovata anche una gestione distinta a record da 8 byte: `0x18e204` cerca un record libero e ne imposta il secondo campo a 1, mentre `0x18e248` lo riporta a zero quando trova il puntatore corrispondente. Il rapporto fra questi record e tutti i consumatori asincroni resta da seguire.

Conseguenza: conservare acquisizione e restituzione originali insieme ai rami che distinguono la proprietà della memoria. Non anticipare il riuso al solo segnale «JPEG terminato». Resta da stabilire quale chiamante completa il rilascio nei discriminanti speciali e nei percorsi d'errore.

## Continuazione: percorso speciale con più descrittori

È stato individuato un rilascio differito coerente con il discriminante `0x10`. Nel tratto `0x1bad24–0x1bad3c`, appartenente alla callback di acquisizione `0x1ba9c4`, il codice controlla quel discriminante e scrive il puntatore `0x1bc67c` in una struttura locale, azzerando anche il contatore byte a stato condiviso +`0xd`. Il puntatore viene scelto anche per un'altra combinazione di stato. La continuazione successiva collega questa registrazione al punto di chiamata; l'esecuzione sulla macchina resta da verificare.

La routine `0x1bc67c` usa il contesto `0x368790` e, quando il byte +`2` vale `0x10`, gestisce una lista di puntatori al campo +`0x24`, un contatore byte +`0xd` e un limite al campo +`0x7c`. Nei rami che terminano il lavoro o raggiungono il limite, scorre i descrittori residui e per ciascuno chiama:

1. `0x18e398 → 0x18e248`, che riporta a zero il campo di stato del record corrispondente nella tabella a elementi di 8 byte;
2. `0x18f310`, che cerca la risorsa associata e può trasferirla da una coda all'altra.

### Le due code

`0x18eb10`, chiamata da `0x18f310`, percorre una coda del contesto `0x368024` al campo +`4`. Confronta il campo +`8` dell'elemento con il campo +`4` del descrittore ricevuto, ricavando così l'elemento associato ai suoi dati. Questa ricerca non equivale al rilascio.

Se trova l'elemento, `0x18f310` chiama `0x18ebb8`. Nel ramo attivo quest'ultima routine:

- chiama `0x2772d8 → 0x2e8bb0` sulla coda al campo +`4`, scollegando l'elemento e decrementandone il conteggio;
- chiama `0x27722c → 0x2e8a54` sulla coda al campo +`0`, ricollegando l'elemento e incrementandone il conteggio.

Il wrapper avanza di quattro byte il puntatore alla struttura della coda in entrambi i casi. È un trasferimento staticamente verificato fra due code, coerente con risorse occupate e disponibili, non una chiamata generica a `free()`.

Questo risolve una parte del dubbio sul discriminante `0x10`: il salto del rilascio semplice può essere coerente con un ciclo a più descrittori e un'altra routine di completamento. Non prova ancora che tutti gli errori arrivino a quella routine. Restano aperti i discriminanti `0x11` e `0x12` e gli invarianti di concorrenza sulle due code.

La percentuale orientativa del progetto resta **10%**: sono migliorate le conoscenze del ciclo delle risorse, ma non è ancora completo il comando fotografico eseguibile da un programma nuovo.

## Continuazione: invocazione della callback e arresto del ciclo

È stata collegata staticamente la registrazione di `0x1bc67c` alla chiamata indiretta a `0x2ec6a4`. La callback viene invocata **all'interno di un ciclo per fotogramma**, prima della decisione di passare all'iterazione successiva. Chiamarla semplicemente «fine dello scatto» nasconderebbe questa distinzione.

### Dal pacchetto locale al ciclo

In `0x1ba9c4` il pacchetto inizia a `fp - 0x16ac`: `0x1baa8c–0x1baa94` ne azzera i primi `0x48` byte, e `0x1bac76–0x1bacaa` scrive la dimensione iniziale `0x48` e il byte di abilitazione a +`0x10` uguale a 1. La scrittura della callback a `fp - 4 × 1445` corrisponde al campo +`0x18`. Il conteggio al campo +`0x3c` riceve il limite del contesto condiviso per il discriminante `0x10`, oppure 1 nell'altro ramo esaminato.

La catena verificata è:

| Passaggio | Osservazione dalle istruzioni |
|---|---|
| `0x1bae98–0x1baea0` | Passa il pacchetto locale a `0x28f610`, con secondo argomento zero |
| `0x28f67c–0x28f6a6` | Azzera l'area a `0x546054`, poi copia 20 byte da pacchetto +`0x10` ad area +`0x10`, conservando abilitazione e callback |
| `0x28f892–0x28f896` | Chiama `0x2ec6f8` con l'area adattata, caricando l'argomento nello slot di ritardo |
| `0x2ec77e–0x2ec786` | Copia `0x75d0` byte nell'area di lavoro a `0x5982b4` |
| `0x2ec7c6–0x2ec7ca` | Chiama il ciclo `0x2ec184` con il pacchetto adattato |
| `0x2ec694–0x2ec6a4` | Se +`0x10` è abilitato e +`0x18` è non nullo, invoca il puntatore con `r0 = 0x5982b4` e `r1 = 0x59fa48` |

Il trasferimento passa da `0xad920`, che gestisce anche sovrapposizioni e inoltra a `0x128c20` il percorso di copia pertinente. La struttura completa, i servizi hardware e gli invarianti di concorrenza non sono ancora ricostruiti: la tabella non costituisce un'API utilizzabile da un nuovo programma.

### Il risultato della callback controlla il proseguimento

`0x1bc67c` normalizza il byte del contesto `0x368790` a +`0x2d` in una parola 0 oppure 1 e la scrive attraverso il secondo argomento, quindi a `0x59fa48` nella chiamata osservata. Per il discriminante `0x10`, aggiorna anche il contatore e segue i rami sui descrittori già documentati. Il significato e i produttori del byte +`0x2d` restano da identificare.

Al ritorno, `0x2ec6a6–0x2ec6be` controlla prima lo stato dell'iterazione. Se è zero, la parola scritta dalla callback vale 1 e non è l'ultimo fotogramma previsto, imposta **`0x2e00043`**. Il ciclo termina quindi senza raggiungere l'iterazione successiva. Nel chiamante `0x1ba9c4`, `0x1baeb0–0x1baeb8` converte proprio questo codice in zero. È coerente con un arresto intenzionale della sequenza trattato come esito riuscito; il nome semantico resta un'inferenza, mentre confronto e conversione sono osservabili nelle istruzioni. Il valore di ritorno della callback non viene usato come risultato dello scatto in questo punto.

### Errori che possono evitare la callback

Non tutti i percorsi attraversano `0x2ec6a4`. Per esempio:

- `0x2ec706–0x2ec710` devia all'uscita se il controllo iniziale restituisce un valore diverso da zero;
- `0x2ec63e` devia a `0x2ec6ea` al superamento del limite del contatore di attesa, imposta `-1` e salta il tratto che chiama la callback. Il limite è un numero di iterazioni, non un tempo misurato.

Questi rami impediscono di assumere che la callback sia una garanzia universale di rilascio. Bisogna ancora seguire i chiamanti e gli altri percorsi di pulizia prima di riusare le risorse da un'applicazione nuova. Non è stata dimostrata una perdita di risorse: manca la ricostruzione completa della gestione degli errori.

La percentuale resta **circa 10%**: è chiuso il collegamento statico registrazione → invocazione per questo percorso, ma non è ancora disponibile un comando fotografico eseguito e verificato sulla S33.

## Verifica e limiti

Lo [script condiviso](../outputs/trace_s33_jpeg.py) verifica ora 16 blocchi, 51 letterali, il descrittore del task video, due destinazioni di tabelle di salti, cinque marcatori e 99 finestre mirate. Include controlli aritmetici sugli offset della disposizione di memoria e del pacchetto della callback, ricostruiti manualmente e marcati come inferenze nella mappa. [Mappa](../outputs/s33_jpeg_map.json), [disassemblaggio](../outputs/s33_jpeg_disassembly.txt), [bundle REA dell'ingresso](../outputs/s33_rea_acquisition_evidence.json), [bundle della preparazione](../outputs/s33_rea_request_evidence.json), [bundle della memoria](../outputs/s33_rea_request_memory_evidence.json), [bundle del rilascio](../outputs/s33_rea_release_evidence.json), [bundle delle due code](../outputs/s33_rea_resource_queues_evidence.json), [bundle dell'invocazione](../outputs/s33_rea_completion_evidence.json).

Record REA `ev_7272f9b05b760c007b3162b83cc16383254ce6b5ddcd889c505370ed5b863b3f`: codice di uscita 0, nessun troncamento. Il controllo conferma i campioni e la riproducibilità delle osservazioni statiche; non esegue il firmware.

La continuazione sulla preparazione è nel record `ev_354400a999cd22b1042164cc17bc4ede29fcc3586378265ad14ba7235644bb8d`: codice 0, nessun troncamento. Il primo record conserva la verifica di 50 finestre, il secondo quella estesa a 58. La ricerca negativa dei puntatori è una pista manuale con il perimetro dichiarato, non una prova di assenza di chiamanti.

La continuazione sulla memoria è nel record `ev_2c4873125aaea8e02a5aadf3da7724dccb107f979373fa67e594917c14aa796b`: codice 0, nessun troncamento, 66 finestre. Gli offset sono inferenze ricavate dalle istruzioni, non una struttura validata tramite esecuzione.

Il rilascio è nel record `ev_0e3c1f9c08c4798ef42040d678b2410d2d2b04dbfd3d26aa522f61dcff309af3`: codice 0, nessun troncamento, 73 finestre. L'[avanzamento del progetto](S33_Stato_progetto.md) resta una stima qualitativa, distinta dal conteggio delle evidenze.

Le due code sono nel record `ev_8e171ca227aa9f954276aff7a6e1da6ea6429be6e01056beea9255827b625c91`: codice 0, nessun troncamento, 85 finestre. Il codice non è stato eseguito sulla macchina.

L'invocazione è nel record `ev_9a650c9b21f8338d878229696e8845c0eae22fb923c21b6b4c244ede3a096f96`: codice 0, nessun troncamento, 99 finestre e 51 letterali. I controlli aritmetici non sostituiscono una verifica dinamica delle strutture.

Il pulsante fisico non è ancora collegato alla catena e non sono stati misurati velocità o consumi. Nessuna immagine installabile è stata prodotta.
