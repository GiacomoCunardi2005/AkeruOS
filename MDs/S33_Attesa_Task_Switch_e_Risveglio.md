# S33 — attesa task, cambio di contesto e risveglio

19 ottobre 2026, analisi statica V1.1. Continuazione di [stack e contesto task](S33_Task_Stack_Contesto_e_GP.md), [semantica eventi](S33_Semantica_Attesa_Eventi_e_Bit_Persistenti.md) e [prototipo ELF](S33_Prototipo_ELF_Offline_e_Integrazione_Fonti.md). Nessuna esecuzione sulla fotocamera.

## Risultato

Il ramo di attesa evento senza termine temporale raggiunge **`0xB2C74`**, salva il contesto del task e lo rimuove dalla lista dei pronti. La segnalazione può reinserirlo; quando viene nuovamente selezionato, lo scheduler ripristina il contesto e riprende da **`0x2C9AC6`**, immediatamente dopo la chiamata bloccante.

Sono verificati **512 cicli sintetici sulle istruzioni decodificate**, inclusi salvataggio/ripristino di r13..25, gp/fp e registri loop, inserimento/rimozione dalle code e ritorno ordinario del servizio inferiore. La successiva selezione del task risvegliato è una precondizione esplicita del modello, non una garanzia di risveglio immediato o fairness.

Questo restringe il requisito R3 di attesa cooperante. Non assegna memoria o un evento ad AkeruOS, non stabilisce l'intero ABI e non chiude avvio/recupero.

## 1. Un chiamante originale e gli argomenti

Il worker Aux entra a `0x15968C`. A `0x159698` chiama il wrapper **`0x158D04`** con:

| Argomento | Valore nel worker | Uso osservato |
|---|---|---|
| r0 | `0x04700004` | ID evento, dal pool `0x159990` |
| r1 | 1 | maschera richiesta |
| r2 | 0 | attesa di almeno un bit |
| r3 | 0, assegnato nel delay slot | nessun termine temporale costruito dal wrapper |

La tabella originale contiene il record evento a **`0x372AB8`**, indice2: magic `0x45564E4C`, ID `0x04700004`, flags2, altri campi inizialmente0. Il suo oggetto inferiore comincia a record+12, cioè `0x372AC4`. L'ID del task Aux `0x04700001` resta un dominio distinto.

Il wrapper risolve e valida il record, passa l'oggetto+12 a `0x23C938`, inoltra opzione in r2 nel delay slot; il trampoline raggiunge **`0x2C9994`** con r4=0 nel proprio delay slot. Non è un'esportazione pubblica Nikon documentata: questi sono ingressi e argomenti ricavati dal codice V1.1.

La guardia inferiore richiede che la halfword **`[K+0x18]` sia0**, con K letto dalla cella `0x369348`. Altrimenti torna con stato grezzo `0x100D`. Sono provati i casi0,1,FFFF; non viene qui attribuito a quel campo il significato completo in tutti i contesti e ingressi da interrupt.

## 2. Quando l'attesa cede davvero l'esecuzione

Le predicate all/any erano già verificate nel [rapporto eventi](S33_Semantica_Attesa_Eventi_e_Bit_Persistenti.md). Il nuovo controllo aggiunge i casi limite con maschera0:

- con opzione nonzero, maschera0 è soddisfatta immediatamente;
- con opzione0, maschera0 non può essere soddisfatta dal confronto any;
- con maschera nonzero già soddisfatta, il servizio può tornare senza bloccare.

Perciò questa API non è un generico «yield» ottenuto passando zero. Il futuro task deve attendere un evento di cui siano definiti produttore, maschera, cancellazione e proprietà.

Nel ramo non soddisfatto, con D=task corrente ed E=oggetto evento:

| Scrittura | Sito / effetto |
|---|---|
| D+`0xC4` = maschera | `0x2C9A2C` |
| bit`0x80` in D+`0x6C` | impostato per all, cancellato per any |
| nodo D+`0xBC` | accodato alla lista evento con sentinella E+8 |
| contatore halfword E+`0x10` | incrementato |
| D+8 = `0x42D` | stato del ramo d'attesa esaminato |
| D+`0x30` = E+8 | riferimento alla coda d'attesa |

Con r3=0, `0x2C9A6E` seleziona `0x2C9AC2 → 0xB2C74`, senza costruire un timeout locale. Questo richiede un futuro segnale o un altro percorso di annullamento: non è una durata finita dimostrata.

## 3. Contesto salvato e rimozione dalla lista pronta

Sia S lo stack all'ingresso di `0xB2C74`. Il servizio sottrae **`0xA4`/164byte** e salva il nuovo sp in D+`0x14`. Questo frame dinamico è distinto dal frame iniziale di184byte studiato nel costruttore dei task.

| Offset da S−`0xA4` | Dato salvato |
|---|---|
| `0x14/18/1C` | r13/r14/r15 |
| `0x20/24/28` | lp_count/lp_start/lp_end |
| `0x2C` e `0x34` | blink, qui `0x2C9AC6` |
| `0x30` | status32 letto all'ingresso |
| `0x5C..80` | r16..25 |
| `0x84/88` | gp/fp |

Il codice imposta bit0 di D+8, poi aggiorna i collegamenti del predecessore e successore del task a `0xB2D04/0A`: D esce dalla lista pronta. L'ultimo store è nel delay slot del salto al selettore **`0xB2DD8`**.

Il modello verifica anche i delay slot nella scansione delle code. Con un altro task pronto viene caricato il suo stack e aggiornato K+`0x1C`; senza un candidato nei tratti esaminati si raggiunge l'idle a `0xB2E08`, dopo l'assegnazione dello stack da K+`0x60`. Sono512casi:256con altro task,256con idle.

Nel passaggio verso idle, `0xB2DEC` legge anche una parola all'indirizzo0 nel delay slot, sebbene il valore venga scartato nel ramo senza altra coda. Il modello dichiara quella parola leggibile e ne varia il contenuto: non dimostra la mappa fisica o gli effetti della lettura sul dispositivo.

Le celle hook `0x36B2B8` e `0x36B2B4` risultano0 nel payload iniziale; il modello assume che restino nulle nei tratti considerati. Non è stata esclusa una loro installazione successiva.

## 4. Segnalazione, lista pronta e ripresa

Il servizio **`0x23C758`** combina i bit tramite OR e controlla i waiter. Quando la condizione è soddisfatta nel ramo senza timeout studiato:

1. rimuove il nodo D+`0xBC` dalla coda E+8 e decrementa il contatore;
2. azzera D+`0x30`, scrive stato2 in D+8 e inserisce D nella lista pronta indicata da D+`0x1C`;
3. azzera i campi D+`0x7C/80/84` del tratto e aggiorna la scelta della lista secondo i confronti presenti;
4. raggiunge il controllo di scheduling `0xB2D34` dopo il proprio epilogo di protezione, nei percorsi visibili.

**Essere nella lista pronta non equivale a essere già in esecuzione.** Il modello verifica separatamente una successiva selezione che arriva a D, sotto i flag ordinari del task, esclusi i percorsi alternativi bit8/bit40 di D+`0x6C`.

Il ripristino ricarica gp a `0xB2E92`, fp nel delay slot `0xB2E9A`, poi usa la parola del frame+`0x34` per `r30`, aggiunge164a sp e salta con `j.f [r30]`. Nel caso studiato torna a **`0x2C9AC6`**, che raggiunge il seguito dell'attesa. Nel modello sono ripristinati r13..25, gp/fp e registri loop; viene osservata la scrittura di status32_l2. Non sono emulati privilegi, effetti hardware di FLAG/j.f o tutte le estensioni CPU.

Con la halfword a E+`0x14` nonzero, il seguito senza timeout imposta ritorno grezzo0; con quella halfword azzerata produce **`0x1039`**, anche dopo il risveglio. Il traduttore `0x17B770` contiene un percorso0→0, verificato staticamente; il wrapper conserva il risultato inferiore in r16 e lo passa al traduttore. Gli stati grezzi non sono automaticamente i codici pubblici del wrapper e non vanno ignorati nel futuro codice.

## 5. Auto-clear e più waiter: differenza verificata

Due scenari aggiuntivi costruiscono due waiter con maschere1 e2, poi segnalano3:

| Configurazione inferiore | Dopo segnale3 |
|---|---|
| auto-clear0 | entrambi pronti, nessun waiter, bit pendenti3 |
| auto-clear1 | primo pronto, secondo ancora in coda, bit pendenti2 |

Nel secondo caso il ramo `0x23C854 → 0x23C862` cancella la prima maschera e termina quella scansione. Una seconda segnalazione con maschera0, che non aggiunge bit, riavvia la scansione e risveglia il secondo waiter già soddisfatto. Questo verifica quel flusso con due waiter e tre operazioni di segnalazione; non è un audit di tutte le interazioni concorrenti o temporizzate.

L'evento Aux originale con flags2 viene inizializzato con auto-clear0. I bit possono quindi permanere, secondo il protocollo già ricostruito. Non è un evento disponibile da riutilizzare per AkeruOS senza analizzare i suoi proprietari.

## Evidenze, limiti e continuazione

[Script](../Python_Trace_Scripts/s33_trace_task_wait_switch.py), [JSON](../Ghidra_Results/ghidra_reports/task_wait_switch/verified_evidence.json), [finestre GNU](../Ghidra_Results/ghidra_reports/task_wait_switch/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_task_wait_switch.py`.

Verificati16hash, roundtrip ELF blocco00, **13finestre/37istruzioni chiave**, record evento e3parole, **512cicli**,8predicate limite,3guardie d'ingresso, ritorno con oggetto invalidato e2scenari a più waiter. Le istruzioni dei tratti eseguiti vengono interpretate da un modello ristretto con memoria sintetica; richieste FLAG sono registrate, non applicate a una CPU. Liste valide, hook nulli, assenza di timeout e successiva selezione sono precondizioni esplicite.

`0x3371C0` contiene soltanto `sleep 0`, nop e ritorno: non realizza qui il salvataggio/accodamento del task appena ricostruito. Non viene proposto come sostituto di un servizio RTOS per il loop AkeruOS.

Prossimo: definire come creare un oggetto di sincronizzazione proprio, i suoi proprietari e durata, insieme a memoria assegnabile e creazione del task personalizzato. Verificare i percorsi di errore e annullamento necessari prima di un binding C. Nessuna modifica del loop o chiamata a indirizzi Nikon viene introdotta senza quei requisiti. R3/R4 e compatibilità V1.0 restano aperte; percentuale invariata.

## Continuazione — caso concreto Load Later, 20 ottobre 2026

Il [protocollo dei caricamenti](S33_Load_Later_Attese_Bit_Persistenti_e_Limite_Ready.md) aggiunge un caso concreto di task/callback ed evento persistente: Load LaterC5830, evento42700002 con auto-clear iniziale0. Sono eseguiti set/clear/query originali in un kernel di laboratorio senza waiter; attesa e servizi esterni delimitati sono simulati.790casi,3072predicate,6iterazioni limitate e8coordinatori chiariscono i limiti dei segnali, senza nuova prova di switch o risveglio reale. Il futuro task AkeruOS richiede ancora oggetto proprio, lifetime, memoria ed errori.
