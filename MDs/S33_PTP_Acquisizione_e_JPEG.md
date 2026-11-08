# S33 — dal comando PTP al lavoro immagini e JPEG

Analisi statica del 18 ottobre 2026. Campione V1.1; log hardware storico V1.0. Nessun accesso alla fotocamera. Continuazione del [percorso Recorder/PTP](S33_Recorder_Dispatch_e_PTP.md).

## Risultato

Aggiornamento: il [percorso CaptureImage](S33_CaptureImage_Completamento_e_ImgMgr.md) è ora collegato allo stesso produttore di lavoro `0x0C`, mediante evento `0x7CE2`, finalizzazione e callback UIAux `0x6602C0`. Le preparazioni e alcuni argomenti differiscono dal percorso PTP: il raccordo non dimostra equivalenza dei rami o del comportamento hardware.

È stato collegato l'handler PTP `InitiateCapture` a un lavoro di tipo **`0x0C`**, eseguito dal gestore immagini tramite callback **`0x1E4C34`**. Un suo ramo arriva al worker JPEG usando **`0x26C8A4`**, attende il worker e legge il risultato. La finalizzazione contiene anche una scrittura JPEG al servizio file già identificato.

Il collegamento al lavoro di tipo `0x0C` è più specifico della precedente analisi del lavoro di tipo 1 (`0x126DD8 → 0x1E77C8`), il cui chiamante iniziale era attribuito a «Take still inside Video». Non si deve sostituire una catena con l'altra nella ricostruzione del comando PTP.

La chiusura è stata successivamente collegata al task **AuxTask2** tramite callback **`0x1E6294`**, come descritto sotto. Restano da verificare selezione dei rami durante lo scatto reale, tutti i consumatori del descrittore e propagazione completa degli errori. La stima complessiva resta circa **10%**.

## 1. Dal descrittore al pacchetto di lavoro

L'handler `0x183950`, registrato per `0x100E`, usa una cella locale a `fp-16` per ricevere il descrittore da `0x1B8F24`. Dopo la preparazione esegue, in sequenza, `0x1B9F6C`, `0x191EA4` e **`0x126D48`**; conserva lo stesso puntatore nella cella locale fra queste chiamate. Le prime due routine leggono campi profondi del descrittore e servizi di configurazione. Non ne viene attribuito qui un contratto completo.

`0x126D48` costruisce a `fp-16` un pacchetto di quattro parole:

| Offset | Valore |
|---|---|
| `+0` | tipo `0x0C` |
| `+4` | puntatore al descrittore ricevuto |
| `+8` | callback `0x1E4C34`, letta dal letterale `0x126DB0` |
| `+12` | callback facoltativa di completamento: secondo argomento nel percorso diretto, zero nel percorso con cella condivisa scelto da `0x1436A4` |

La [verifica successiva degli esiti](S33_Esiti_ImgMgr_e_Chiusura.md) distingue i due percorsi di callback e il risultato del worker dall’esito della chiusura.

Nel chiamante PTP il secondo argomento è zero (`0x183A7A`). La routine può inoltre chiamare `0x13B490`, `0x13B198` e `0x1707D8` prima dell'invio. Questi effetti restano parte del protocollo originale.

A `0x126D9E` il pacchetto viene passato a **`0x15A570`**. Questa routine acquisisce un elemento, copia **16 byte** a elemento+8, pubblica l'elemento e segnala il worker. La copia evita che il worker conservi il puntatore al pacchetto sullo stack del produttore; **il descrittore puntato dal pacchetto conserva invece la propria durata separata**.

La [continuazione sul contratto di invio](S33_Esiti_ImgMgr_e_Chiusura.md) risolve il pool di 60 record da 24 byte e precisa il ritorno: errori preliminari oppure risultato dell'ultima segnalazione evento. L'esito dell'accodamento non viene conservato; il ritorno dell'invio non è da solo una conferma transazionale.

## 2. Invocazione della callback nel gestore immagini

Nel task `0x15A478`, già attribuito a `ImgMgrIRPTask`:

- `0x15A4CE` legge la callback da elemento+16, cioè pacchetto+8;
- `0x15A4D6` la invoca passando **elemento+8**, cioè l'inizio del pacchetto, nel delay slot;
- `0x15A4EE` conserva il risultato della callback a **`0x3672FC`**;
- `0x15A4F0 → 0x2400CC` rende il record nuovamente selezionabile azzerando il marcatore descrittore a elemento+12 e la cella corrente `0x36A66C`; questo corpo non lo reinserisce nella coda dei buffer fotografici. Al termine dei lavori viene segnalato il completamento.

`0x15A5C8` attende uno dei segnali originali sul servizio `0x70000A` e, se l'attesa riesce, legge proprio `[0x3672FC]`. Il risultato del lavoro immagini è quindi disponibile separatamente dalla sola pubblicazione nella coda.

`0x1E4C34` verifica che il pacchetto non sia nullo e che la prima parola sia `0x0C`. Legge il descrittore da pacchetto+4 e lo memorizza nel contesto di elaborazione a `0x497730 + 152*4 = 0x497990`. Il campo di stato separato è a `0x497730 + 154*4 = 0x497998`. I fattori quattro derivano dalle istruzioni ARC `.as`, non da offset in byte copiati alla lettera dal disassemblaggio.

Questi indirizzi descrivono il campione statico; non costituiscono strutture C complete o memoria da riutilizzare arbitrariamente in un'applicazione nuova.

## 3. Ramo del lavoro che richiede JPEG

La callback ha più rami, fra cui quello selezionato dal byte `0x368D88+0xC0`. Non è stato osservato quale ramo esegua la V1.0 nello scatto del log. Nel ramo che raggiunge `0x1E50CA`, la callback alterna verifiche di stato e stadi di elaborazione (`0x1E2744`, `0x1E3160`, `0x1E3458`, `0x1E3828`) prima di arrivare condizionalmente a **`0x1E4434`**, chiamata a `0x1E51AA`.

Nel percorso interno di `0x1E4434`:

| Sito | Operazione |
|---|---|
| `0x1E4636` | pubblica i parametri con `0x13B758` |
| `0x1E464E`, `0x1E4658` | configura servizi del blocco 02 tramite `0x60D854`, `0x60D8E4` |
| `0x1E4668` | chiama `0x60DA24` con zero |
| **`0x1E466E`** | invia al worker JPEG la callback **`0x26C8A4`**, letta da `0x1E46E4` nel delay slot |
| `0x1E4ABC` | attende il worker con `0x15A798` |
| `0x1E4ACE` | legge il blocco risultato con `0x13B7E4` |
| `0x1E4ADC..0x1E4AE0` | nel ramo senza precedente errore legge anche il campo di stato del contesto |

Questo collega il nuovo percorso PTP al servizio JPEG già descritto in [richiesta e risultato JPEG](S33_JPEG_Richiesta_e_Risultato.md). Il task JPEG esegue la callback registrata e segnala la fine indipendentemente dal suo ritorno: il controllo del risultato rimane necessario.

## 4. Scrittura JPEG e gestione delle risorse

Dopo gli stadi condizionati, la callback chiama **`0x1E4AEC`** a `0x1E51CA` per la finalizzazione, conservando un errore precedente se già presente.

Nella finalizzazione, un ramo prepara i byte **`FF D9`** a `0x1E4B48..0x1E4B50`, poi richiede a `0x28D66C` il selettore **6**, modalità **1**, a `0x1E4BB8`. Questo selettore e modalità passano da `0x137B54` alla catena di scrittura file già verificata. **Precisazione del ramo:** `r13` riceve lo stato da contesto+`154*4`; a `0x1E4B32..0x1E4B3C`, stato zero salta la scrittura e va a `0x1E4BC4`. L'aggiunta di `FF D9` richiede quindi uno stato già non nullo, oltre al controllo `0x13AF78 != 0`. È coerente con un recupero di errore, non dimostra il finale normale riuscito. Le scritture dei blocchi JPEG compaiono invece nel worker `0x26C8A4`, per esempio a `0x26CD12` con selettore 6/modalità 1.

La chiamata indiretta a **`0x1E4BEE`** legge il campo +4 della tabella ottenuta da `0x22C5B8`. Una configurazione originale è stata risolta:

1. `0x141B04` prepara una tabella locale di `0x3C` byte a `fp-0x3C`.
2. Scrive il puntatore **`0x18EE98`** a +0 e **`0x18F260`** a +4, letti da `0x141C94` e `0x141C98`.
3. Chiama `0x22C58C`, che controlla i due puntatori e copia `0x3C` byte a **`0x4BE52C`**.
4. `0x22C5B8` restituisce questa stessa tabella se i due puntatori iniziali sono non nulli.

`0x18F260` consulta il contesto delle risorse di acquisizione, azzera campi e può chiamare `0x18E354` e `0x18E248`, già collegati ai record delle risorse. Questa callback ha quindi effetti da conservare sul ciclo delle risorse. La sola risoluzione a `0x18F260` **non stabilisce una chiusura file**. Sono possibili altre configurazioni della tabella; non è stato dimostrato che quella descritta sia l'unica attiva in ogni modalità.

### Chiusura differita trovata nel task AuxTask2

Il collegamento mancante è un'altra callback registrata dalla stessa finalizzazione:

| Passaggio | Evidenza statica |
|---|---|
| Conservazione dell'handle | `0x1E4BD6..0x1E4BDE` copia descrittore+`0x48` nel contesto `0x368D88+0x5C = 0x368DE4` |
| Attesa precedente | `0x1E4BFC` può invocare una callback opzionale e `0x1E4C1A` chiama `0x159898`, che attende il bit 8 del servizio `0x04700005` |
| Registrazione | `0x1E4C20` chiama `0x159824` con funzione **`0x1E6294`**, letta dal letterale `0x1E4E44`, e secondo argomento zero |
| Pubblicazione | `0x1E4C26` chiama `0x159860`, che copia la funzione pendente da `0x3672B0+0x10` al campo attivo `+0x0C = 0x3672BC`, cancella bit 8 e imposta bit 4 |
| Invocazione | Il task **`0x1596B8`** attende bit 4, legge la funzione da `0x3672BC` e la chiama a **`0x1596D8`** |
| Fine callback | Il task imposta bit 8 a `0x1596DC`, senza usare il ritorno della callback |

Il nome **AuxTask2** è verificato sui byte originali del blocco 01: descrittore `0x3723A8`, ingresso `0x1596B8`, nome a `0x376410`. Il campo `+0x14` scritto da `0x159824` non viene passato come argomento nella chiamata osservata del task; la callback di chiusura usa variabili globali proprie.

La callback **`0x1E6294`**, se `0x13AF78 != 0` e il byte **`[0x368ED2] == 0`**, acquisisce la sincronizzazione `0x700007`, legge l'handle da `0x368DE4` e chiama:

```text
0x1E62BA → 0x28D66C(6, 2, handle, 0, 0)
         → ramo 0x28D920
         → 0x137B74
         → 0x21828C
         → 0x12D604
         → 0x1F22C0 → callback del driver al campo +0x10
```

`0x21828C` risolve l'handle e chiama `0x12D604` con l'indirizzo della cella locale che lo contiene. Questa catena era già nota per un altro lavoro; ora il suo ingresso è collegato al lavoro PTP `0x0C` tramite **finalizzazione → registrazione → AuxTask2 → callback di chiusura**. I controlli precedenti del dispatcher file possono ancora evitare la chiusura e restituire un errore.

La conservazione separata dell'handle spiega perché la callback di chiusura può lavorare senza ricevere direttamente il descrittore. Non dimostra che tutti gli altri consumatori abbiano finito di usarlo o che il suo buffer possa essere restituito anticipatamente.

### Due varianti dell'attesa del gestore immagini

`0x15A5C8` usa il getter `0x13B1C0`, che legge il byte **`0x366C78`**:

| Valore del byte | Segnale atteso sul servizio `0x70000A` |
|---|---|
| zero | bit `0x2`, segnalato dal worker immagini dopo il lavoro |
| non zero | bit **`0x400`**, che la callback `0x1E6294` può segnalare dopo il suo tratto di chiusura |

Il ramo a `0x1E62C8..0x1E62E8` verifica il getter e lo stato del bit 2 prima di segnalare `0x400`. La routine `0x126D48` seleziona un valore 0/1 consultando `0x1436A4` e chiama `0x13B198`, che può aggiornare i byte `0x366C78/0x366C79` dopo una precedente attesa. Il significato utente dello stato letto da `0x1436A4` e gli invarianti temporali fra i task non sono stabiliti qui. Non è corretto scegliere già una delle due varianti come quella della cattura reale.

### Errore di chiusura e fine della callback

Il ritorno di `0x28D66C` a `0x1E62BA` non viene preservato o controllato prima della chiamata di rilascio `0x1594A4`. Anche AuxTask2 segnala il proprio bit 8 senza conservarlo. L'eventuale segnale `0x400` è quindi collegato all'esecuzione della callback, **non a una verifica esplicita di chiusura riuscita in questi punti**. La visibilità di eventuali errori tramite altri stati o log resta da cercare.

## 5. Errori e risposta PTP: limite del contratto attuale

Il codice dell'handler PTP contiene tre punti che impediscono di usare la sola risposta al comando come prova di corretta elaborazione:

| Chiamata | Controllo osservato immediatamente dopo |
|---|---|
| `0x183A7C → 0x126D48` | il ritorno di invio al gestore immagini non viene confrontato con zero; viene controllata la cella del descrittore |
| `0x183A9A → 0x15A5C8` | il risultato del lavoro atteso non viene controllato esplicitamente; seguono altre operazioni e controlli con ritorni propri |
| `0x183AF6 → 0x15AFDC` | il risultato della registrazione callback viene sovrascritto da `0x2001` nel ramo successivo |

Esistono altri rami di errore nel chiamante, fra cui quelli che costruiscono `0x2002`. I punti sopra non dimostrano da soli un difetto del firmware: potrebbero esserci vincoli precedenti, controlli condivisi o gestione degli errori in altri componenti. Dimostrano però che **non è ancora disponibile un contratto «risposta PTP riuscita ⇒ JPEG e chiusura riusciti»**.

La callback che emette `0x400D` ha inoltre un protocollo separato nel task UIAux. Per AkeruOS occorre conservare o ricostruire gli esiti di invio, elaborazione, scrittura e chiusura, e stabilire quando tutti i consumatori hanno rilasciato il descrittore. Segnalazione di fine, risultato del lavoro e persistenza sulla SD sono requisiti distinti.

## Evidenza riproducibile e lavoro restante

Lo [script esistente](../Python_Trace_Scripts/s33_trace_recorder_dispatch.py) è stato esteso: controlla i nuovi letterali, il tipo `0x0C`, la callback JPEG, la configurazione della tabella di risorse, gli alias dell'handle e della callback di chiusura, il descrittore AuxTask2 e il byte della variante di attesa. Verifica dimensioni e SHA-256 dei 16 blocchi, prepara gli ELF da payload originali e ne controlla il roundtrip; conserva **81 finestre**, comprese le successive evidenze sui [marcatori S2](S33_S2_Marcatori_e_PTP_Vendor.md), nel [disassemblaggio](../Ghidra_Results/ghidra_reports/s33_recorder_dispatch_disassembly.txt) e i collegamenti nei campi `ptp_image_job` e `ptp_deferred_close` del [JSON](../Ghidra_Results/ghidra_reports/s33_recorder_dispatch.json). Esecuzione completata con codice 0. I controlli non simulano né eseguono il firmware.

Prossimi nodi: propagazione dell'errore di chiusura, invarianti dei consumatori del descrittore, rami d'errore, selezione e sincronizzazione delle varianti e ingresso fisico S2. La presenza della catena di chiusura non prova la persistenza dopo perdita di alimentazione. Non sono stati modificati firmware, foto o configurazione della fotocamera.
