# S33 — avvio del runtime e contratto di creazione dei task

Analisi statica del 18 ottobre 2026, firmware Nikon S33 V1.1. Nessuna esecuzione, creazione di task sul dispositivo o modifica dei payload. I log hardware esistenti sono V1.0. Continuazione del [capitolo 5](Nikon_Coolpix_S33_Capitolo_5.md), ora con finestre GNU e controlli mirati. **Avanzamento complessivo orientativo: circa 10%, invariato.**

## Risultato per AkeruOS

L'avvio applicativo originale è suddiviso in preparazione comune, selezione del percorso e inizializzazioni asincrone eseguite dai task Aux. Sono collegati ai descrittori originali nove siti di richiesta di creazione di task, inclusi WindowMgr, UIAux e Recorder.

Il wrapper `0x158E78` ha due canali distinti: ritorna uno stato e scrive l'ID del task in una cella fornita dal chiamante. Nel creatore sottostante esiste inoltre un ramo per un template passato tramite puntatore, da studiare come possibile base per un nuovo task AkeruOS. Non è ancora un'API pronta, né un punto di inserimento validato.

## 1. Tabella originale e fase comune

La tabella `0x372388` contiene **53 record da 32 byte**, seguiti da un record interamente zero. Lo script verifica nomi e ingressi nei payload originali. Fra questi record, soltanto **RTOSINIT**, ID 1 e ingresso **`0x167A20`**, ha il bit 0 degli attributi impostato. L'interpretazione come attributo di avvio automatico resta coerente con MQX, senza attribuire versione o comportamento del kernel dal solo bit.

La catena verificata è:

```text
RTOSINIT 0x167A20
  → 0x17B894
  → se ritorno zero: 0x0C5B68
       → 0x0C5D08, preparazione comune
       → se ritorno zero: selezione del percorso applicativo
            valori locali 4 o 5 → 0x0C5BEC
            altri valori       → 0x0C5DDC, con ulteriori controlli
```

`0x17B894` inizializza strutture tramite più servizi e percorre record da `0x38` byte, con controlli su bit. Non si attribuisce qui a ogni struttura una semantica completa.

La selezione in `0xC5B68` legge un valore a offset 110 da una base caricata, e nel caso 3 consulta ulteriori predicati che possono trasformarlo in 4 o 5. Le etichette utente dei percorsi restano sconosciute.

Nella preparazione comune, un ritorno nonzero da **`0xC63D8`** evita la parte successiva che richiede WindowMgr e inizializza altri servizi. Questo controllo consulta una risorsa e una soglia, poi un ulteriore servizio: è una precondizione concreta, senza averne ancora attribuito il requisito hardware esatto.

Nel ramo che procede, l'ordine delle chiamate include:

1. `0xC5D78 → 0x15AF4C`: richiesta WindowMgr e, sotto condizioni aggiuntive, UIAux.
2. `0xC5D7C → 0x159060`: inizializzazione di strutture e registrazioni dell'interfaccia, con valori 640/480 nel corpo.
3. Ulteriori servizi e controlli.
4. `0xC5DCE → 0x159710`: configurazione della sincronizzazione e richieste dei tre task Aux.

È l'ordine statico delle chiamate, non una misura dell'ordine in cui i task iniziano a essere schedulati o diventano pronti.

## 2. Richieste di creazione collegate ai nomi originali

Tutti i siti sotto chiamano `0x158E78`. Le associazioni ID, nome e ingresso sono ricavate dai record originali, non dal solo contesto del chiamante.

| Chiamante / sito | ID template | Nome originale | Ingresso |
|---|---|---|---|
| `0x15AF4C / 0x15AF52` | `0x00300002` | WindowMgr | `0x15AF0C` |
| `0x15AFA4 / 0x15AFC4`, ramo condizionale | `0x00300003` | UIAux | `0x15B06C` |
| `0x159710 / 0x159758` | `0x04700001` | AuxTask | `0x15968C` |
| `0x159710 / 0x159762` | `0x04700002` | AuxTask2 | `0x1596B8` |
| `0x159710 / 0x15976C` | `0x04700003` | AuxTask3 | `0x1596E4` |
| `0x141B04 / 0x141B20` | `0x40100002` | Recorder Still Task | `0x12E720` |
| `0x141B04 / 0x141B30` | `0x40100003` | Recorder Video LV Disp Task | `0x1638D8` |
| `0x141B04 / 0x141B40` | `0x40100005` | Take still inside Video | `0x1637BC` |
| `0x130840 / 0x13086C` | `0x40100006` | Recorder Still LVAUX Task | `0x13091C` |

`0x141B04` viene chiamata anche durante la fase principale a `0xC5E5E`, e a sua volta richiama `0x130840` dopo le tre richieste iniziali, con controlli di stato. Questo collega parte dell'avvio ai servizi Recorder già incontrati nel percorso fotografico.

L'ID template di un task, l'ID di un evento interno e l'handle del task creato appartengono a domini differenti. Per esempio, `0x04700002` identifica il template AuxTask2, mentre `0x04700005` è il valore usato dal protocollo di eventi di quel worker; non vanno sostituiti fra loro.

## 3. Le fasi asincrone di 0xC5DDC

Il ramo principale supera prima una preparazione che può restituire un errore. Nella parte successiva programma callback sui task Aux già creati:

| Task | Callback | Registrazione | Avvio del lavoro |
|---|---|---|---|
| AuxTask | `0xC605C` | `0xC5E2E → 0x159778` | `0xC5E32 → 0x1597B4` |
| AuxTask3, se `0xCF440()` è nonzero | `0xC651C` | `0xC5E46 → 0x1598D0` | `0xC5E4A → 0x15990C` |
| AuxTask2 | `0xC60A8` | `0xC5E56 → 0x159824` | `0xC5E5A → 0x159860` |
| AuxTask | `0xC60C8` | `0xC5E70 → 0x159778` | `0xC5E74 → 0x1597B4` |
| AuxTask3 | `0xC61C8` | `0xC5E7E → 0x1598D0` | `0xC5E82 → 0x15990C` |

La fase usa attese prima del riuso degli slot: fra queste `0x1597EC` per AuxTask, `0x159898` per AuxTask2 e il puntatore a **`0x159944`** per AuxTask3, caricato dal letterale `0xC5EA8` e chiamato più volte indirettamente.

I tre worker hanno cicli distinti che attendono il proprio evento, leggono uno slot callback, la chiamano se non nulla e segnalano il completamento prima di ripetere il ciclo. Le callback non ricevono automaticamente il campo adiacente allo slot come argomento nel punto di invocazione osservato; usano il contesto previsto dal codice originale.

La tabella rappresenta l'ordine di pubblicazione nel corpo, con lavoro potenzialmente concorrente e rami. Non è una lista di funzioni da chiamare tutte in modo sincrono. Non sono state chiuse tutte le dipendenze delle callback, né tutti i canali di esito e timeout. Il completamento del worker non equivale da solo a sensore, display e storage pronti.

## 4. Contratto parziale di 0x158E78

| Registro all'ingresso | Uso verificato |
|---|---|
| `r0` | ID del template cercato nella tabella fissa `0x372388` |
| `r1` | Selettore fra due varianti del servizio sottostante |
| `r2` | Puntatore scrivibile alla cella che riceve l'ID del task |

La ricerca avanza di 32 byte fino all'ID richiesto o al terminatore. Se manca l'ID, restituisce **`0x200201`**; quel ramo non dimostra che la cella di uscita venga azzerata.

Nel ramo trovato, legge il parametro di creazione da record+`0x18` e chiama:

- `0x23C990` se il selettore è zero;
- `0x23C940` se è nonzero. Questa variante, dopo la creazione, scrive 3 nel campo +8 del descrittore del task. La variante zero contiene invece operazioni che raggiungono lo scheduler.

Non si attribuisce qui un nome ufficiale come «blocked» al valore 3. È una differenza concreta fra varianti, da preservare finché gli stati del kernel non sono ricostruiti.

Se il servizio restituisce un ID nonzero, il wrapper lo scrive attraverso `r2` e **ritorna zero**. Se il servizio restituisce zero, il wrapper scrive zero attraverso `r2` e ricava lo stato mediante `0x17B770`, dopo il servizio di ripristino del contesto. Il puntatore di uscita non viene controllato per nullità nel ramo trovato: non è un argomento facoltativo dimostrato.

Questo chiarisce perché il ritorno di `0x158E78` non è l'ID del task. Inoltre, creare un task non dimostra che abbia completato l'inizializzazione interna: il protocollo di disponibilità va ricostruito separatamente.

## 5. Pista per un template AkeruOS

Entrambe le varianti raggiungono **`0x2C9AE0`**. Il suo ramo con primo argomento nonzero cerca il template attraverso un puntatore del contesto kernel, con passo 32. La [verifica successiva del bootstrap](S33_Bootstrap_Kernel_e_Pool_Iniziale.md) identifica l’assegnazione da configurazione: in quel percorso la tabella coincide con `0x372388`, come nel wrapper. Altre configurazioni o modifiche successive non sono state escluse.

Il ramo con **primo argomento zero** interpreta invece il secondo argomento come un puntatore a template, ne legge il campo +24 come parametro di creazione e imposta un discriminante interno a 1 prima di chiamare **`0x29F3A8`**.

Questa è una pista per integrare un task con template fornito dall'applicazione, senza limitarsi agli ID già presenti nella tabella fissa del wrapper. Non prova ancora che un template nuovo possa essere costruito liberamente: allocazione e durata del record, stack, registri iniziali, indirizzo d'ingresso e contesto globale richiedono l'analisi di `0x29F3A8` e delle sue dipendenze.

Lo scheletro corrente `AkeruOS/main.c`, con ciclo infinito e contatore, non è ancora un task cooperante con questo runtime. Non sono stati aggiunti cast di indirizzi, nuove chiamate al firmware o una patch di avvio.

## Prossimo passo e requisiti aperti

La [continuazione su stack e contesto](S33_Task_Stack_Contesto_e_GP.md) ricostruisce ora `0x29F3A8 → 0x2C9C30` e un percorso di ripristino dello scheduler. Verificata la copia del template personalizzato e il `gp` ereditato; aggiornata la build minima con `-mno-sdata`. Restano aperti i requisiti elencati sotto, oltre al collegamento completo al bootstrap.

Per R3, seguire `0x29F3A8` fino alla costruzione di stack e contesto iniziale, poi collegare il puntatore dei template kernel e l'ingresso TBIB → TBM. Usare il risultato per specificare un task AkeruOS minimo osservabile e cooperante, prima di implementarne il punto d'inserimento.

Restano aperti memoria libera, compatibilità ABI/compilatore, gestione degli overlay, confezionamento e recupero. R2 resta parziale sugli errori e sulla disponibilità dei buffer: l'avvio ricostruito non sostituisce il contratto fotografico.

## Riproduzione

Eseguire `python3 s33_trace_runtime_startup.py`. Lo [script](../Python_Trace_Scripts/s33_trace_runtime_startup.py) verifica hash e dimensioni dei **16 blocchi**, tutti i **53 template**, nomi, ingressi, terminatore, letterali, istruzioni selezionate e destinazioni delle chiamate. Esegue roundtrip ELF identico del blocco 00; produce **22 finestre GNU ARC700** nel [disassemblaggio](../Ghidra_Results/ghidra_reports/runtime_startup/gnu_verified.txt) e il [JSON](../Ghidra_Results/ghidra_reports/runtime_startup/verified_evidence.json), con hash dello script. Esecuzione completata con codice 0.

Le evidenze sono statiche e riferite alla V1.1. Non dimostrano esecuzione sulla V1.0, raggiungibilità in ogni modalità o la chiusura di tutti i requisiti di avvio.

## Continuazione — caso concreto ComMgrTask, 20 ottobre2026

[USBDEVMODE e strutturaUSB](S33_USBDevModeSwitch_Identita_e_Scritture_Struttura_USB.md) raccorda il record3727C8,ID02100001,ingresso138E20/nomeComMgrTask alla chiamata138E4C→158E78. La creazione precede l’assegnazione del defaultMSDC nella funzioneC5EC0. L’evento omonimo è un oggetto distinto,record373880. Otto casi del wrapper con servizio di creazione simulato verificano argomenti, ritorno,stack e preservazione della struttura; non è una nuova creazione/schedulazione reale. Restano produttori della notifica e ordine runtime.
