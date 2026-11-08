# S33 — handshake del task MCU nel TBIB e dati INFO

Analisi statica V1.1, 19 ottobre2026. Continuazione dell'[ordine dei callback finali](S33_Ordine_Callback_TBIB_e_Confine_Pulizia.md). Nessun accesso hardware.

## Risultato

Il percorso principale che raggiunge l'uscita del kernel TBIB esegue prima un handshake con il task denominato **`MCUCTRL_Task`**: imposta il bit30 dell'evento **`0x03200002`** e attende il bit31. Il task riconosce il bit30, chiama un servizio di cancellazione timer e pubblica il bit31 **senza confrontare il ritorno del servizio timer**.

Il wrapper richiedente forza poi il proprio ritorno a0, senza propagare il ritorno dell'attesa quando questa ritorna normalmente al chiamante. Pertanto l'ack e il ritorno0 non costituiscono da soli una prova di arresto dei controller.

La seconda chiamata prima dell'uscita kernel copia invece sei coppie di parole nel blocco condiviso **INFO a `0x900`**. Sono dati trasmessi alla fase successiva, non un'altra routine di arresto hardware.

## 1. Ordine prima dell'uscita kernel

Nel ramo che raggiunge `0x01000414`:

```text
0x01000416 → servizio di stato con argomento3
0x0100041A → 0x01002314, richiesta/attesa del task MCU
0x0100041E → 0x010006EC, copia dei dati INFO
0x01000424 → 0x01006D20, uscita kernel con stato conservato in r17
```

È un tratto del percorso principale, sotto le guardie precedenti; non dimostra che ogni avvio o ogni errore lo attraversi. La tabella dei task originale collega l'ingresso `0x01002154` al nome `MCUCTRL_Task`, ID template `0x03200001`. Questo ID è distinto dall'evento `0x03200002`.

## 2. Richiesta bit30 e attesa bit31

`0x01002314` chiama due servizi di preparazione e poi:

| Sito | Operazione osservata |
|---|---|
| `0x01002324 → 0x01006998` | evento `0x03200002`, maschera **`0x40000000`** costruita nel delay slot |
| `0x01002332 → 0x010069E0` | stesso evento, maschera **`0x80000000`**, opzione1 e argomento temporale0 |
| `0x0100233C` | r0=0 nel delay slot del ritorno |

Il primo wrapper raggiunge `0x0101EE20`, il cui tratto iniziale combina i bit correnti con la maschera tramite OR. Il wrapper di cancellazione `0x010069BC`, usato dal task, raggiunge invece `0x0101EF74`, che applica AND con il complemento della maschera.

Nel livello inferiore dell'attesa, opzione nonzero richiede che `(bit_correnti & maschera)==maschera`. Per questa singola maschera viene quindi richiesto il bit31. Non viene qui emulata la durata dell'attesa o l'intero percorso di scheduling.

Il ritorno del setter non viene confrontato prima dell'attesa. Se l'attesa ritorna, il wrapper forza0 prima di tornare al suo chiamante. Questo descrive il canale di ritorno locale: i servizi inferiori e l'eventuale gestione fatale degli errori non sono modellati come chiamate reali.

## 3. Risposta del task e limite del timer

Il ciclo del task attende l'evento con maschera **`0x60F7F773`**, opzione0 e argomento temporale0. Legge poi i bit restituiti e li cancella esplicitamente tramite `0x010069BC`.

Dopo le elaborazioni precedenti sugli altri bit, a `0x010021FC` controlla il bit30:

- se non è impostato, torna al ciclo di attesa;
- se è impostato, legge il valore dalla struttura `0x01041180`, lo passa a **`0x010038B8 → 0x01013AD8`**, quindi imposta il bit31 dello stesso evento.

Il servizio inferiore contiene percorsi di errore e operazioni su oggetti timer; il wrapper superiore non dimostra da solo che un timer sia stato trovato e cancellato. **Tra il ritorno della chiamata timer e la pubblicazione del bit31 non c'è un confronto del risultato.** Il modello verifica che l'ack venga richiesto per ritorni sintetici0,1,FFFFFFFF e valori casuali.

Dopo la pubblicazione, il task raggiunge la chiamata allo scheduler `0x0100B5B0`. L'ack precede questa chiamata: non è una prova che il task sia già stato distrutto o abbia ceduto il processore prima che il richiedente riprenda.

Le due preparazioni del richiedente non aggiungono qui un arresto hardware accertato: `0x0100BFA8` ritorna0; `0x0100C158`, sotto la propria guardia, chiama `0x0101611C`, che nel campione è un semplice ritorno, e aggiorna un byte di stato.

## 4. Inizializzazione e persistenza dei bit

L'evento è il secondo record da56byte della tabella `0x01041864`, a **`0x0104189C`**:

```text
campo+0 = 0x45564E4C
campo+4 = 0x03200002
flags+8 = 2 nel payload
```

Il creatore prende il solo bit0 dei flags e lo passa al costruttore dell'oggetto, che azzera i bit iniziali e salva quel parametro nel campo di auto-clear. Per flags2 il parametro è0. Il percorso di attesa cancella automaticamente la maschera solo se il bit0 del campo di auto-clear è impostato.

L'evento appena creato parte quindi con bit azzerati e, per questa configurazione, non consuma automaticamente il bit31 quando l'attesa riesce. La richiesta di stop non cancella esplicitamente un precedente bit31 nel tratto esaminato. **Non è dimostrata una barriera riutilizzabile per richieste ripetute:** occorre provare freschezza dell'ack e tutti gli altri scrittori, oltre all'ordine di inizializzazione.

## 5. Copia finale nel blocco INFO

La sequenza `0x0100029E..2A2` inizializza:

```text
parola[0x01041100+0x20] = 0x900
```

La cella è **`0x01041120`**, riletta dalla routine di copia. Un altro tratto di inizializzazione scrive a `0x900` la parola `0x4F464E49`, cioè i byte `INFO`. Altri eventuali scrittori del puntatore non sono esclusi globalmente.

La routine `0x010006EC` risolve la sorgente tramite un pool scalato:

```text
align4(0x010006EE) - 133*4 = 0x010004D8
parola[0x010004D8] = 0x01090000
```

Per j=0..5 copia due parole32bit:

```text
INFO+0x3C+8*j = parola[0x01090000+8*j]
INFO+0x40+8*j = parola[0x01090004+8*j]
```

Con il puntatore preparato sopra, la destinazione è **`[0x93C,0x96C)`**,48byte. La sorgente è un'area runtime: i valori delle12parole non sono ricavati dal solo payload TBIB. Non viene ancora attribuita alle sei coppie una semantica di allocazione o di buffer hardware.

Un interprete delle istruzioni della copia verifica256 insiemi di12parole, ordine degli store e intervallo esatto. Non legge RAM reale e non dimostra che un consumatore TBM abbia già utilizzato quei dati.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_tbib_worker_stop.py), [JSON](../Ghidra_Results/ghidra_reports/tbib_worker_stop/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/tbib_worker_stop/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_tbib_worker_stop.py`.

Verificati identità contenitore/TBIB, checksum e roundtrip ELF, **19 finestre, 42 istruzioni chiave, 9 parole, record evento, 256 scenari richiesta/ack e 256 copie delle sei coppie**. Nel modello i servizi sono stub con ritorni forniti; frame, scheduling, timer e periferiche non vengono eseguiti.

Prossimo: collegare i produttori delle sei coppie e i consumatori INFO nel TBM; completare freschezza dell'ack e condizioni dei controller prima della transizione. Restano aperti memoria assegnabile, inserimento AkeruOS, caricamento modificato, recupero e compatibilità V1.0.
