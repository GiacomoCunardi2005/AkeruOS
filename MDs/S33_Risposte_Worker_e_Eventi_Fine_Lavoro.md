# S33 — risposte dei worker ed eventi di fine lavoro

Analisi statica V1.1, 19 ottobre 2026. Continuazione di [cicli e mailbox](S33_Cicli_Alternativi_e_Mailbox.md). Nessuna esecuzione hardware.

## Risultato

Collegato un intero percorso di risposta: **worker `0x343280` → record `0x424800` → mailbox inversa → handler `0x247364` → evento `0x09900020`, bit 2**.

Il record conserva il risultato del lavoro, ma il ricevente **segnala l'evento senza confrontare quel valore con zero**. L'attesa dell'evento è quindi distinta dall'interpretazione dell'esito. È stato inoltre trovato un wrapper che non confronta il risultato della propria attesa prima di aggiornare uno stato software. Avanzamento funzionale orientativo invariato: circa 10%.

## 1. Registrazione di worker e ricevente

Nel tratto **`0x15C684..0x15C69C`**:

| Richiesta | Funzione passata | Destinazione nel ramo ammesso dal setter |
|---|---|---|
| `0x23FA04` | `0x247364`, pool `0x15C738` | `0x424300`, handler delle risposte |
| `0x23FAE4` | `0x343280`, pool `0x15C73C` | `0x424404`, callback di lavoro |

Entrambi i setter contengono controlli precedenti allo store. Il collegamento è quindi condizionato all'ammissione della registrazione e ai valori che rimangono installati a runtime.

Il primo percorso di lavoro, distinto, registra **`0x342FF8`** tramite `0x3371E8`; il relativo ramo ammesso conserva il puntatore a **`0x424204`**. La nuova verifica non ricostruisce tutti i suoi comandi, ma attribuisce un ramo di risposta descritto sotto.

## 2. Produzione della risposta nel secondo worker

**`0x343280`** legge la prima parola della richiesta. Nel ramo con selettore **0**, prende la struttura indicata da richiesta+8 e seleziona un callback da alcuni suoi campi. Se lo invoca, a **`0x3432E0`**, conserva il ritorno in r0 fino alla costruzione del record:

| Campo | Contenuto scritto |
|---|---|
| `0x424800 + 0` | Tipo risposta **1** |
| `0x424800 + 4` | Valore di r0, risultato del callback nel ramo che lo esegue |

Altri sottorami possono raggiungere il record senza chiamare un callback. Non si attribuisce un significato universale a ogni valore restituito dal lavoro.

Il worker passa poi il puntatore **`0x424800`** a **`0x2D528C`**, produttore della mailbox inversa **`0x428400`**. L'oggetto di risposta è distinto dalla cella mailbox: la mailbox trasporta un puntatore, non una copia del record.

C'è anche un limite locale: un selettore richiesta diverso da zero salta a `0x3432F4`, oltre l'inizializzazione del record, e attraversa comunque la pubblicazione. Non è provato che tali richieste raggiungano il servizio normalmente; il chiamante deve quindi essere studiato prima di parlare di risposte obsolete realmente osservate.

## 3. Consumo e pubblicazione dell'evento

Il ciclo **`0x23FA50`** attende e pulisce bit **4** dell'evento **`0x03400006`**, poi chiama **`0x2D524C`** per prelevare la mailbox. Quando ottiene un puntatore, invoca l'handler installato a **`0x424300`**.

L'handler **`0x247364`** controlla tipo risposta **1**. Nel ramo corrispondente:

1. Legge record+4 e lo conserva nella parola **`0x36AD58`**.
2. Chiama `0x23FA38(1)`, che aggiorna uno stato del servizio.
3. Pubblica **maschera 2** sull'evento **`0x09900020`** mediante `0x158CBC`.

Fra la lettura del payload e la pubblicazione non c'è un confronto con zero. Un valore nonzero viene conservato e può essere notificato allo stesso modo: il bit significa che questo percorso ha elaborato una risposta di tipo 1, senza certificare il successo del lavoro.

La mailbox viene liberata prima dell'handler, come nel protocollo già ricostruito. Anche qui la cella libera non dimostra che il destinatario abbia già letto o interpretato l'esito.

## 4. Limite del wrapper che attende il completamento

**`0x247338`** chiama `0x158D04` con evento **`0x09900020`**, maschera 2, poi chiama `0x158CE0` per pulire la stessa maschera. **Non confronta il ritorno dell'attesa prima di proseguire**. Imposta infine **byte `0x36AD54 = 1`**.

Il byte aggiornato non costituisce, da solo, una prova che l'attesa sia riuscita. Inoltre l'esito del lavoro è conservato separatamente in `0x36AD58`: chi usa il servizio deve distinguere attesa, stato del wrapper e payload della risposta. Non si deduce qui che un errore di attesa avvenga realmente o che il byte rappresenti una garanzia pubblica dell'API.

## 5. Un ramo di risposta del primo worker

Nel primo worker **`0x342FF8`**, un ramo chiama **`0x33F8F4`**, scrive tipo **6** a **`0x42852C`** e il ritorno a **`0x428530`**, poi pubblica il puntatore tramite **`0x33739C`** sulla mailbox inversa `0x428200`.

Il ricevente registrato **`0x293AB8`**, nel caso tipo 6, può conservare record+4 in **`0x36C2AC`** e pubblica maschera **1** sull'evento **`0x04D00001`**. In questo ramo il campo zero salta la copia ma non la pubblicazione. È un altro esempio di separazione fra payload e notifica, senza attribuire ancora il significato completo della funzione di elaborazione.

Queste catene non sono una prova di persistenza JPEG: i callback di elaborazione, la durata dei buffer e il consumatore finale dei risultati restano da collegare alla pipeline fotografica.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_alternate_response_events.py), [JSON](../Ghidra_Results/ghidra_reports/alternate_response_events/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/alternate_response_events/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_alternate_response_events.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **12 finestre, 13 collegamenti diretti e 24 istruzioni chiave**, oltre ai pool dei callback. Nessuna prova hardware o modifica del firmware.

Prossimo: produttori della struttura lavoro, significato e consumatori di `0x36AD58`, contratto dei callback selezionati e loro rapporto con i buffer immagine e la chiusura del file.

## Continuazione sulla provenienza dei callback

Il [rapporto descrittore/callback](S33_Descrittore_Worker_e_Selezione_Callback.md) collega configurazione, descrittore e copia del payload fino alla funzione invocata, e confronta la sorgente con il ramo diretto. Il consumatore finale di `0x36AD58` non è ancora attribuito.
