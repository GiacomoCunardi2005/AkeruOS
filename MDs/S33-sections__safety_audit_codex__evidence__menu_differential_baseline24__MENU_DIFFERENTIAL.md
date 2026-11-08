# HiddenMenu: esecuzione differenziale dopo la biforcazione

19 ottobre 2026, R4/diagnostica. **Eseguiti 24 scenari P-code: CMP3/stato3 e CMP1/stato1, con gli stessi esiti filesystem simulati.** Il percorso positivo raggiunge in entrambi la main e la callback reale di inizializzazione della radice. I casi negativi mostrano invece una differenza concreta nel fallback NAND. Non sono dimostrate inizializzazione completa, visualizzazione o chiusura di una sessione reale.

## Metodo e input dichiarati

[Runner](../S33-sections/safety_audit_codex/evidence/menu_differential_baseline24/run_menu_differential.py), [probe Java](../S33-sections/analysis_ghidra/scripts/ProbeMenuDifferential.java), [manifest](../S33-sections/safety_audit_codex/evidence/menu_differential_baseline24/menu_differential_verified.json), [log](../S33-sections/safety_audit_codex/evidence/menu_differential_run.log), [12 finestre GNU](../S33-sections/safety_audit_codex/evidence/menu_differential_gnu.txt). Riproduzione:

```bash
python3 S33-sections/safety_audit_codex/run_menu_differential.py
python3 S33-sections/safety_audit_codex/menu_state_dependencies.py
python3 S33-sections/safety_audit_codex/menu_state_queue_verify.py
```

CMP3 e CMP1 sono i due campioni già verificati: SHA-256 rispettivamente `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39` e `932281f89b840a45dc1b050dac52d5250f040ea6576b94696b55f3b93e123f1c`. Gli hash sono ricontrollati, senza modificare i file. Linguaggio `ARCompact:LE:32:aliasfix`, con [validazione precedente](../S33-sections/safety_audit_codex/alias_fix_verified.json) controllata prima delle prove; nessuna nuova semantica CPU aggiunta.

Sono precaricati i payload verificati 0/1/2/4/5/8/9 alle rispettive basi candidate, con payload0 scelto dalla variante effettiva. Non è una prova della loro residenza contemporanea sulla macchina. Stack e registri sono di laboratorio. Si forniscono al manager `0x366E94` tabella `0x3F5900`, conteggio197, nessun oggetto corrente/precedente iniziale e hook nulli; busy o tabella assente sono varianti esplicite. I test evento separati impostano invece la radice come oggetto corrente/precedente. Non si deduce che il boot reale produca questi stessi contesti quando lo stato è3 oppure1.

**Solo quattro servizi filesystem sono sostituiti con risultati dichiarati:**

| Ingresso | Risposta fornita dal test |
|---|---|
| `0x12B8E8` | Stato volume e byte di disponibilità tramite r1 |
| `0x12B7E4` | Esito del tentativo di mount |
| `0x12B888` | Esito del rilascio |
| `0x26E6BC` | Esito lookup e byte attributi tramite r1 |

Il ritorno zero rappresenta successo nel contratto locale; i valori nonzero1/5 sono errori scelti dal modello, senza attribuirli a specifici errori fisici Nikon. Il servizio `0xCDA24`, wrapper `0x12BBB8`, controllo reale dell'attributo `0x10` a `0x18B45C`, resolver, manager e dispatcher UI sono invece eseguiti in P-code. Ogni simulazione è marcata `MOCK` nella traccia. Non viene imposta un'apertura del menu e non si sostituisce il risultato del manager.

## Risultati comparati

| Caso | CMP3/stato3 | CMP1/stato1 |
|---|---|---|
| HiddenMenu disponibile con attributo0x10 | Richiesta20 → main radice → callback ingresso | Identico nel tratto registrato |
| HiddenMenu assente; marcatore NAND assente | Due sonde, poi continuazione normale | Una sonda, poi continuazione normale |
| HiddenMenu senza bit0x10; NAND assente | Due sonde, nessuna apertura | Una sonda, nessuna apertura |
| HiddenMenu assente; marcatore NAND presente con bit0x10 | **Richiesta ID0x4A** | **Nessuna apertura; continuazione normale** |
| Errore stato volume | Due tentativi; nessuna apertura | Un tentativo; nessuna apertura |
| Volume da montare, mount riuscito | Lookup, rilascio, callback ingresso root | Identico nel tratto registrato |
| Mount fallito | Due tentativi; nessuna apertura | Un tentativo; nessuna apertura |
| Manager occupato | Richiesta20, rifiuto reale, ritorno0 | Identico |
| Registro menu assente | Richiesta20, rifiuto reale, ritorno0 | Identico |
| Evento ingresso0x4401, test separato | Callback root raggiunta | Identico |
| Evento uscita0x0480, test separato | Callback root richiede `ResetCameraConfirmMenu`, ID0x84 | Identico fino al limite del modello |
| Record evento0x80 già estratto, test separato | Filtrato dalla radice; ritorno al loop | Identico |

Il runner confronta esattamente i suffissi registrati a partire dalla prima sonda HiddenMenu oppure dall'ingresso del test evento: **7 casi con suffisso identico, 5 divergenti**, per ciascuna coppia. Non normalizza registri o istruzioni per ottenere uguaglianza; esclude il prefisso che esegue il getter/confronto con i diversi input. Rimangono diversi per costruzione il byte RAM dello stato e l'immediato del confronto nei due programmi.

Il suffisso comprende PC, r0/r1/SP/blink, eventi, sonde, richieste di apertura, risultati e hash delle celle RAM tracciate come scritte dopo l'impostazione degli input. L'hash include indirizzi, lunghezze e ultimi valori delle celle, non la storia ordinata di ogni scrittura né tutti i registri CPU. Esclude gli spazi register/unique/auxregs e le impostazioni iniziali del modello. È acquisito prima dell'istruzione che arresta il caso, evitando di includere effetti del passo fallito. Nei casi positivi coincidono anche **245 byte RAM in9 intervalli tracciati**. Il byte `0x366880` resta al proprio valore di ingresso in tutti i casi, verificato da assert; ciò non prova l'assenza di altri writer su percorsi non eseguiti.

## Quanto è stata eseguita l'inizializzazione

Dal selettore si eseguono davvero `0x1453E4 → 0x14507C → 0x145180`, l'evento0x4403 e poi0x4401. Sono raggiunti main root `0x7CC6DC` e callback ingresso `0x7CC714`, dopo aver inizializzato anche oggetti risorsa attraverso il framework. La richiesta20 è quindi collegata alla callback tramite esecuzione, oltre al precedente collegamento statico.

Il caso positivo esegue **2.139 step P-code riusciti**, più due risposte simulate dei servizi; il campo `steps=2141` conta anche questi interventi. `pcode_steps` conta i passi riusciti del helper: gli slot di ritardo possono essere eseguiti nello stesso passo della call/salto, quindi non è un conteggio di tutte le istruzioni fisiche ARC né una misura dei tempi. Poi Ghidra si ferma a `0x3342B4`: GNU ARC700 decodifica `muludw`, mentre il linguaggio usa `asm_instruction_05`, privo di implementazione. Non si fornisce un risultato aritmetico fittizio per superare l'arresto. Il manager non ha ancora pubblicato la radice come corrente in questo caso. **Callback raggiunta non equivale a inizializzazione terminata o schermata visibile.**

Nel test separato dell'evento0x0480 viene eseguita `0x7CC88C → 0x1453E4(0x84,0)` e si entra nel ciclo vita del descrittore `0x99F218`. Arresto successivo a `0x1786F2`, lettura non inizializzata da `0x1C`, dopo4.641 step P-code riusciti. Il nome del caso `root_exit_event` indica un candidato d'uscita software: non è verificata la corrispondenza con un tasto fisico. Non è stata inviata una conferma reset0x2180 e non è dimostrato un ritorno innocuo al modo fotografico.

## Coda eventi e altre dipendenze dallo stato

Il caso `queue_filtered_event` parte nel vero corpo WindowMgr a `0x15AF34`, con un record già estratto nello stack: destinatario0, evento0x80, argomento0. Esegue caricamenti, `0x169E1C`, risoluzione dell'oggetto corrente, dispatcher, main root e filtro reale; **dopo245 step P-code ritorna a `0x15AF2E`**, sede del prossimo pop. Non sono eseguiti pop del ring, attesa bloccante, interrupt o una sessione continua dopo l'inizializzazione.

Il [controllo indipendente dello stato e della coda](menu_state_dependencies.md) aggiunge32 finestre GNU e un riancoraggio di altre4 finestre/18istruzioni/6pool. Conferma WindowMgr `0x15AF0C`, ring `0x367BBC`, record12byte `0x47A848`, pop `0x17BD4C`. La richiesta sincrona `0x1453E4` e il loop eventi sono operazioni distinte.

Quel controllo identifica inoltre altri rami reali che distinguono1 da3 presso `0xC62BA`, `0x134F98/0x134FA0`, `0x134FFE`, `0x13614E`. Nei25intervalli downstream selezionati non trova una dipendenza diretta dallo stato, ma hook e chiamate transitive restano aperti. **Non è dimostrata equivalenza globale fra stato3 e stato1.** La ricerca dei riferimenti nei16payload resta limitata ai pattern e agli ingressi descritti nel rapporto.

## Continuazione e decisione flash

Prossimo ostacolo concreto dell'inizializzazione: identificare e convalidare la semantica dell'estensione `muludw` e dei registri risultati per questa CPU, prima di aggiungerla a un modello separato. Per l'uscita serve l'origine dell'oggetto mancante al limite `0x1786F2`; per la coda vanno collegati estrazione e attesa al contesto effettivamente inizializzato. Non sostituire istruzioni o interi backend UI per dichiarare completata la sessione.

Questi risultati chiariscono il comportamento della selezione e alcuni effetti successivi sotto input controllati. Non verificano updater residente V1.0, scrittura flash, atomicità, recupero o compatibilità hardware. **NO-GO invariato**, firmware e macchina intatti, avanzamento funzionale AkeruOS circa10% invariato.

La [validazione finale](../S33-sections/safety_audit_codex/evidence/menu_differential_final_validation.log) ha controllato manifest/sorgenti/listati correnti,24scenari,7coppie uguali/5diverse, snapshot RAM tracciata, preservazione degli input e del decoder, collegamenti e alias dell'indice. I tre script Python compilano; Ghidra ha compilato ed eseguito il nuovo probe Java. Il log `menu_differential_tracking_attempt.log` conserva un tentativo fallito del verificatore mentre includeva lo spazio temporaneo P-code `unique`: non è una prova sul firmware; il controllo finale riguarda esclusivamente `ram`.
