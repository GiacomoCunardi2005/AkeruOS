# S33 — descrittore del worker e selezione dei callback

Analisi statica V1.1, 19 ottobre 2026. Continuazione di [risposte ed eventi](S33_Risposte_Worker_e_Eventi_Fine_Lavoro.md). Nessuna esecuzione hardware.

## Risultato

Ricostruito il passaggio della funzione da eseguire: **configurazione `0x367490` → descrittore `0x392328` → richiesta `0x424700` → worker `0x343280`**. Il builder seleziona il callback a configurazione+`0x38`, se presente; altrimenti usa quello a +`0x3C`.

Il ramo diretto legge le stesse due sorgenti. È quindi chiarita la provenienza locale del puntatore invocato dal worker, ma l'identità effettiva delle funzioni installate e l'equivalenza completa fra i due rami restano aperte. Non è stato attribuito un lettore finale del risultato `0x36AD58`. Circa 10% funzionale invariato.

## 1. Configurazione e descrittore intermedio

L'ingresso di lavoro a **`0x15C4E8`** carica **`0x392328`** come base del descrittore, tramite il pool `0x15C714`. Nel tratto del builder **`0x15C612..0x15C654`** copia puntatori e parametri nella struttura, poi legge la configurazione a **`0x367490`** dal pool `0x15C71C`.

La selezione locale inizializza entrambe le celle del descrittore:

| Condizione | Descrittore+`0x38` | Descrittore+`0x34` |
|---|---|---|
| Configurazione+`0x38` nonzero | Copia configurazione+`0x38` | Zero |
| Configurazione+`0x38` zero | Zero | Copia configurazione+`0x3C` |

I due campi non sono semplicemente valori ereditati da una richiesta precedente: questo tratto li assegna esplicitamente. Rimane possibile che anche il callback di fallback sia nullo; le invarianti che lo impedirebbero non sono provate qui.

Gli indirizzi delle due sorgenti sono **`0x3674C8`** e **`0x3674CC`**. La loro identificazione come campi di funzione deriva dalla successiva chiamata indiretta, non da simboli Nikon originali.

## 2. Copia nel payload della richiesta

**`0x247398`** riceve il descrittore e copia molti campi nella richiesta statica **`0x424700`**. In particolare:

| Sorgente | Destinazione |
|---|---|
| Descrittore+`0x34` | Richiesta+116 (`0x74`) = `0x424774` |
| Descrittore+`0x38` | Richiesta+120 (`0x78`) = `0x424778` |

Il produttore **`0x247310`** assegna tipo richiesta 0 e costruisce **richiesta+8 = richiesta+64 = `0x424740`**. Passa poi il puntatore alla mailbox mediante `0x2D522C`. La struttura trasportata dalla mailbox rimane una richiesta con un puntatore al payload interno; non è un pacchetto autonomo di callback e dati copiato per ogni invio.

Ne consegue la corrispondenza usata dal worker:

```text
payload = richiesta+0x40
payload+0x34 = cella fallback 0x424774
payload+0x38 = cella preferita 0x424778
```

La ricostruzione descrive i valori scritti dai rami verificati. Non esclude mutazioni concorrenti della richiesta o del descrittore prima del consumo.

## 3. Scelta e chiamata nel worker

Nel ramo tipo richiesta 0, **`0x343280`** legge il payload da richiesta+8. Prima carica **payload+`0x38`**. Se nonzero lo usa; altrimenti carica **payload+`0x34`**. Prepara argomenti diversi secondo il ramo selezionato e raggiunge la chiamata **`jl_s.d [r13]` a `0x3432E0`**.

Questo collega il puntatore invocato alle sorgenti della configurazione del builder. Non dimostra ancora il nome o il contratto del callback: i produttori di `0x3674C8/CC` devono essere ricostruiti.

Il ritorno del callback confluisce nella risposta tipo 1 già studiata, poi nel payload conservato a `0x36AD58` e nell'evento. La nuova verifica non attribuisce un consumatore finale di quel risultato; non viene presentato come già controllato dalla pipeline fotografica.

## 4. Il ramo diretto usa le stesse sorgenti

Nel percorso diretto del servizio, **`0x15C6CA`** legge configurazione+`0x38`. Se quel campo non seleziona il primo ramo, il tratto **`0x15C740..0x15C75A`** legge configurazione+`0x3C`. La chiamata indiretta avviene a **`0x15C75C`**.

Qui il ritorno viene confrontato immediatamente con zero: se nonzero, il codice chiama **`0x15C058`**, il cui trattamento completo non è verificato in questo rapporto. Nel percorso mailbox, invece, il valore attraversa record, ricevente ed evento secondo il protocollo già ricostruito.

La coincidenza delle sorgenti dei callback riduce un'incertezza, ma non basta a dimostrare equivalenza di argomenti, ordinamento, gestione degli errori o durata dei buffer. Servono l'identità delle funzioni e il contratto dei chiamanti. In particolare la selezione di un ramo non dimostra che si tratti sempre di JPEG o di scrittura file.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_worker_descriptor_callbacks.py), [JSON](../Ghidra_Results/ghidra_reports/worker_descriptor_callbacks/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/worker_descriptor_callbacks/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_descriptor_callbacks.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **8 finestre, 4 collegamenti diretti e 25 istruzioni chiave**, più i pool di configurazione, descrittore e funzioni di invio/attesa/ricezione.

Prossimo: scrittori dei callback in `0x3674C8/CC`, condizioni che scelgono percorso diretto o mailbox e interpretazione del risultato prima del riuso dei buffer. Nessuna misura hardware o prova di persistenza del JPEG.

## Continuazione sullo scrittore della configurazione

Il [rapporto installazione callback](S33_Installazione_Callback_da_Configurazione.md) risolve lo scrittore dei due campi a partire da un descrittore di cinque parole nell’input di `0x15DF98`. Restano aperti i valori reali dei descrittori e l’identità delle funzioni.
