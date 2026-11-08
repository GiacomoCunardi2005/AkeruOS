# S33 — slot interrupt runtime e gruppi di callback SD

Analisi statica V1.1, 19 ottobre 2026. Continuazione di [registrazione dei gestori](S33_Registrazione_Gestori_e_Buffer_Trasferimento.md). Nessuna esecuzione hardware.

## Risultato

L'inizializzatore **`0x16D3F0`** registra il dispatcher **`0x2640E0` nello slot runtime 4** e **`0x264308` nello slot runtime 9**, tramite il registrar `0x231428`. È risolto anche il consumatore dello slot dedicato `0x36B324`: il dispatcher **`0x2660A8`** viene registrato come ID logico **`0x0904`** e richiama fino a tre callback non nulle.

La catena delle notifiche SD è quindi collegata più a monte. Gli slot runtime non vengono ancora identificati con un indirizzo di vettore CPU o con una consegna hardware osservata. Avanzamento funzionale orientativo invariato: circa 10%.

## 1. Installazione degli slot runtime

`0x16D3F0` modifica `aux_irq_lev`, esegue preparazioni e carica dal pool il registrar **`0x231428`**. Fra le richieste verificate:

| Slot passato in r0 | Funzione in r1 | Dato associato in r2 |
|---|---|---|
| 4 | `0x2640E0` | 0 |
| 9 | `0x264308` | 0 |

Il registrar legge la radice kernel da **`0x369348`** e usa campi scalati `ld.as`:

| Campo kernel | Impiego nel corpo |
|---|---|
| +`142*4 = 0x238` | Puntatore alla tabella di registrazione |
| +`139*4 = 0x22C` | Limite inferiore dell'indice |
| +`140*4 = 0x230` | Limite superiore dell'indice |

Dopo i controlli calcola **`record = tabella + 12*(slot − limite_inferiore)`**. Conserva la funzione precedente, scrive quella nuova a record+0 e il dato associato a record+8, dentro la sezione critica già ricostruita. Il ritorno ordinario contiene la funzione precedente: non è automaticamente un codice di successo zero.

Questa prova attribuisce le richieste dell'inizializzatore a una tabella del runtime. Il puntatore effettivo della tabella, i suoi limiti dopo avvio e l'ingresso CPU che la consulta devono ancora essere collegati prima di attribuire indirizzi assoluti ai vettori.

## 2. Consumatore degli slot dedicati

**`0x2660A8`** carica la base **`0x36B320`** e tratta in sequenza:

| Offset | Cella | ID di registrazione già risolto |
|---|---|---|
| +4 | `0x36B324` | `0x2001` |
| +8 | `0x36B328` | `0x2002` |
| +`0x0C` | `0x36B32C` | `0x2004` |

Per ciascuna cella, se il puntatore è nonzero lo invoca. Il dispatcher non applica qui un distinto controllo hardware prima di ognuna: richiama tutte le callback installate, nell'ordine indicato. I loro corpi possono poi applicare guardie proprie.

Il ramo SD precedentemente risolto conserva **`0x2689FC`** nella prima cella. Quest'ultimo gestore controlla registri MMIO e può richiamare la callback del trasferimento fino alla pubblicazione dell'evento SD. La nuova prova chiude il punto aperto sul consumatore di `0x36B324`, senza dimostrare che gli slot contengano questi valori in ogni stato runtime.

## 3. Abilitazione del gruppo e registrazione di 0x0904

**`0x265FE8`** richiede il bit 13 nell'ID ricevuto e usa una halfword alla base `0x36B320` come stato del gruppo. Nel ramo in cui questa halfword vale **`0x2000`**, esegue:

```text
registrazione_logica(0x0904, 0x2660A8)
richiesta_abilitazione(0x0904, 0xFF)
```

Sono rispettivamente le chiamate **`0x16D898`** e **`0x16D7E8`**. Poi combina l'ID con la halfword precedente e la riscrive. La costruzione del chiamante `0x16DD36` passa `0x2001` a questo servizio soltanto dopo aver salvato il gestore dedicato.

Un limite di propagazione è esplicito: **il ritorno della registrazione a `0x26600E` non viene confrontato prima della richiesta successiva**. Il risultato conservato in r13 deriva invece dalla chiamata successiva. Non si assume quindi che un ritorno finale zero certifichi ogni preparazione interna.

## 4. Tabella e dispatcher del gruppo 0x0900

Il registrar seleziona per gli ID del gruppo `0x0900` la tabella **`0x424C30`**. Nei byte iniziali:

| Proprietà | Valore |
|---|---|
| Puntatori letti dall'intestazione | `0x0FEF0040`, `0x0FEF002C` |
| Conteggio | 14 record |
| Passo | 8 byte |
| Voce per ID `0x0904` | Indice 10, record `0x424C8C` |
| Indici bit del record | 3 e 3 |
| Cella callback | `0x424C90`, inizialmente zero |

Il dispatcher **`0x264308`**, passato allo slot runtime 9 dall'inizializzatore, usa questa tabella. Controlla i bit indicati dal record rispetto a due letture halfword MMIO e verifica che il campo funzione sia nonzero. Solo allora raggiunge **`jl [r0]` a `0x264376`**.

La catena statica risolta è:

```text
slot runtime 9 → dispatcher 0x264308
→ voce logica 0x0904 → 0x2660A8
→ slot dedicato 0x2001 → 0x2689FC
→ slot callback del trasferimento → evento SD
```

L'altra catena usa slot runtime 4, dispatcher `0x2640E0` e voce logica `0x0402 → 0x267F20`, già attribuita. Sono due percorsi distinti che dipendono da registrazione, stato delle maschere e callback attive.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_transfer_irq_dispatch.py), [JSON](../Ghidra_Results/ghidra_reports/transfer_irq_dispatch/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/transfer_irq_dispatch/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_transfer_irq_dispatch.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **7 finestre, 6 collegamenti diretti e 23 istruzioni chiave**, oltre ai pool e ai 14 record della tabella. Le chiamate indirette sono attribuite tramite i pool e gli store, non osservate sulla macchina.

Prossimo: origine e uso della tabella kernel+`0x238`, ingresso CPU degli slot 4/9, gestione dei ritorni di registrazione e coerenza del buffer. Nessuna prova di persistenza fisica del JPEG.

## Continuazione: catena statica dei vettori

Il [rapporto vettori](S33_Vettori_Interrupt_e_Tabella_Runtime.md) risolve generatore, stub numerati e ingresso comune fino alla tabella kernel+`0x238`, raccordando staticamente gli slot 4/9. Restano aperti valore assoluto di `int_vector_base`, abilitazione e osservazione runtime.
