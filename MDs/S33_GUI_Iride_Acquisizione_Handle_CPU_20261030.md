# Iride — acquisizione e validità della handle

Il 30 ottobre 2026 ho eseguito in GNU ARC700 il wrapper originale V1.1 `0x18B928`, l'acquisizione `0x235A1C`, la guardia `0x235ABC`, l'helper `0x18B954` e la richiesta `0x235B0C`, con registri MMIO inerti e servizi sostituiti nel banco. Il banco chiama l'helper solo dopo un ritorno zero dell'acquisizione e passa la halfword realmente scritta dall'acquisizione; non impone direttamente la handle all'helper.

Nei due casi acquisiti con successo, la generazione iniziale `0x1234` viene restituita come handle; la richiesta di stato 1 o 9 viene accettata, il byte software cambia, viene programmato tramite fixture il callback `0x235AE4` e la generazione diventa `0x1235`. Nel caso con generazione iniziale `0xFFFF`, la richiesta accettata la porta a `0x0000`: il campo è una halfword e il wrap è osservato in CPU. Questo impedisce di trattare la handle come un identificativo univoco per sempre; non misura quante richieste si verifichino sul dispositivo.

Negli altri casi:

- Incrementando **artificialmente** la generazione dopo l'acquisizione, la guardia originale rifiuta la handle precedente; lo stato e i registri simulati restano invariati.
- Se lo stato richiesto è già quello software, la guardia riesce e viene chiamata la fixture di rilascio, senza richiesta di movimento.
- Se la fixture dell'acquisizione restituisce 3, il wrapper restituisce 3 e la cella di output conserva la sentinella `0xBEEF`; il banco non chiama l'helper. Il marker scritto prima dell'acquisizione rimane 1 nel banco: la sua pulizia e il suo significato su questo percorso non sono dimostrati.
- Se la fixture impone il dispositivo occupato dopo acquisizione, helper ritorna 0, stato e MMIO restano invariati, compare il byte sintetico `0x15` ed è chiamata la fixture cleanup.

Tutti i sette casi conservano lo stack e la traccia non entra in `0x158D04`. Nei casi di acquisizione riuscita il codice originale pone il bit 2 del campo software di proprietà, ma il rilascio e la cleanup sono fixture: il banco non prova che tale bit venga successivamente ripulito. Il callback differito viene solo passato al post simulato, non eseguito.

[Script ripetibile](../Python_Trace_Scripts/s33_verify_iris_claim_async_cpu.py), [sette casi](../Risultati/GUI_S33/iris_claim_async_cpu_20261030T153641Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/iris_claim_async_cpu_20261030T153641Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/iris_claim_async_cpu_20261030T153641Z/fixture_patches.json). Codice originale e dati sono controllati contro il dump V1.1. Acquisizione della risorsa sottostante, lock, servizio post, rilascio e cleanup sono simulati: non si dimostrano esclusione reciproca reale, scheduler, callback, movimento, f/, AE o collegamento GUI. Nessuna scrittura su fotocamera o firmware installato; **NON_INSTALLARE**.
