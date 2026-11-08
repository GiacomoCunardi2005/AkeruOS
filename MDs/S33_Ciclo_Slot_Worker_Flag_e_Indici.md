# S33 — ciclo degli slot worker, flag e indici

Analisi statica V1.1, 19 ottobre 2026. Continuazione dell'[origine dei puntatori](S33_Origine_Puntatori_Worker_e_Aree_Riservate.md). Nessuna esecuzione hardware.

## Risultato

Collegati pubblicazione e lettura dei flag delle tre tabelle di buffer, selezione dello slot richiesto e azzeramento successivo dei flag. Due aggiornamenti degli indici sono ricondotti a **`(indice+1) mod 4`**, verificato per tutti i **256 valori di ingresso byte**.

Questo chiude una parte della contabilità degli slot. Non prova che il flag significhi elaborazione riuscita, che ogni consumatore hardware abbia terminato, o che tutti gli scrittori degli indici rispettino lo stesso protocollo. Stima funzionale invariata: circa 10%.

## 1. Tre indici separati

| Cella | Uso osservato |
|---|---|
| `0x392144` | indice usato dal produttore per scegliere griglia/destinazione |
| `0x392145` | copia dell'indice produttore precedente, quando avanza |
| `0x392146` | indice richiesto dal chiamante del consumatore |
| `0x36759C = configurazione+0x10C` | indice registrato dopo aver osservato il flag nonzero |

Le prime tre celle appartengono alla struttura `0x3920B8`, inizialmente azzerata su `0x94` byte. Non vengono confuse fra loro: il consumatore esaminato carica l'indice da +`0x8E`, mentre il produttore usa +`0x8C`.

## 2. Pubblicazione del flag da parte del produttore

Il tratto `0x15C786..7D8` legge lo stato della struttura, poi scrive 1 a un byte indicizzato:

| Stato della struttura produttore | Base flag, più indice byte |
|---|---|
| 0 | `0x39213C` = struttura+`0x84` |
| 1 | `0x392140` = struttura+`0x88` |
| altro, sotto la guardia locale | `0x392138` = struttura+`0x80` |

Il task ha anche percorsi che saltano questa pubblicazione, per esempio il ramo di `0x15C6A0`. Il tratto di pubblicazione non legge il codice worker conservato a `0x36AD58`. Pertanto non viene equiparato il flag a un codice di successo zero.

Nel percorso che mantiene r1=1 fino a `0x15C7F4`, il task copia il vecchio indice in `0x392145` e aggiorna `0x392144`. I percorsi con r1 diverso da 1 saltano questi due store.

L'aritmetica di `0x15C800..80C`, su un byte iniziale i, produce `(i+1) mod 4`. La verifica copre anche i=255, che produce 0. Questo dimostra il limite dell'uscita di questo aggiornamento; non dimostra l'invariante globale dell'indice prima di ogni lettura o per ogni scrittore.

Il tratto finale segnala **evento `0x08200010`, maschera `0x20`**. Il pool è risolto dall'istruzione PCL scalata a `0x15C80E`: `align4(site)-68*4 = 0x15C6FC`. Questo evento del task è distinto dalla precedente notifica del worker `0x09900020/bit2`.

## 3. Attesa del consumatore

La routine **`0x15CF0C`** riceve un indice in r0 e un selettore in r1. Usa la base `0x392128` e sceglie le stesse tre famiglie di flag tramite offset +`0x14`, +`0x18` o +`0x10`, poi somma l'indice senza moltiplicarlo.

Se il flag è zero, il ramo normale chiama `0x19A774` con argomento 5 e torna a leggerlo. La routine contiene anche uscite e altre guardie: non viene presentata come un'attesa sempre conclusa con successo né viene attribuita un'unità temporale all'argomento 5.

Quando il flag è nonzero, **`0x15CF54`** registra l'indice in `0x36759C`. Nel sito chiamante **`0x15D496..4A8`**:

1. r0 viene letto da `0x392146`;
2. r1 viene letto da configurazione+`0x104`;
3. viene chiamata l'attesa;
4. solo il ritorno nonzero prosegue verso `0x24863C`.

Lo stato del produttore arriva dalla struttura, mentre qui il selettore arriva dalla configurazione. **L'equivalenza dei due valori nel ciclo runtime non è ancora provata.** La corrispondenza delle basi dei flag è una proprietà degli accessor verificati, non una prova che ogni chiamante scelga sempre la stessa famiglia.

`0x24863C` è un passo successivo della pipeline; i suoi consumatori e il completamento fisico restano da chiudere. La registrazione dell'indice da sola non prova il rilascio dell'area.

## 4. Azzeramento dei flag e avanzamento della richiesta

Il tratto **`0x15DAD8..DB28`**, ammesso quando configurazione+`0xA8` vale zero, legge il selettore configurazione+`0x104` e l'indice richiesto `0x392146`.

| Selettore | Store osservati |
|---|---|
| 0 | azzera flag `0x39213C+indice`; questo tratto non avanza l'indice richiesto |
| 1 | azzera flag `0x392140+indice`; aggiorna `0x392146=(indice+1) mod 4` |
| altro | azzera flag `0x392138+indice`; aggiorna `0x392146=(indice+1) mod 4` |

L'indirizzo del flag è costruito con l'indice vecchio prima dell'incremento: il codice azzera lo slot appena indicato, non quello successivo. Il ramo selettore 0 modifica anche un altro campo di controllo; non viene dedotto che il suo indice non avanzi mai altrove.

Questi store provano un ciclo locale **flag 0 → pubblicazione 1 → osservazione → azzeramento 0**, sotto guardie e chiamanti coerenti. Resta da verificare se il momento dell'azzeramento coincide con l'ultimo uso hardware del buffer. Non vengono dedotte garanzie di ordinamento memoria o esclusione concorrente da semplici store byte.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_worker_slot_cycle.py), [JSON](../Ghidra_Results/ghidra_reports/worker_slot_cycle/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/worker_slot_cycle/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_slot_cycle.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 8 finestre, 8 collegamenti diretti, 38 istruzioni chiave e 16 pool**, più l'identità modulo4 per 256 byte iniziali. Nessuna prova hardware o di persistenza JPEG.

Prossimo: seguire `0x24863C` fino all'ultimo uso della destinazione e attribuire gli altri scrittori degli indici. Restano aperte coerenza dei selettori, capienza, lettore finale del risultato worker e riuso sicuro.


## Continuazione: destinazione al livello registri

Il [rapporto sulla destinazione](S33_Destinazione_Worker_e_Registri_Indirizzo.md) collega un percorso condizionale ai registri0x0FE9811C/120. Il setter programma l’indirizzo senza attendere il completamento: il momento dell’ultimo uso resta aperto.
