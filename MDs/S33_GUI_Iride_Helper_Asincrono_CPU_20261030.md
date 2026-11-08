# Iride — helper con richiesta senza attesa

Il 30 ottobre 2026 ho verificato in CPU GNU ARC700 il candidato V1.1 `0x18B954(indice, handle)`, individuato in precedenza staticamente. Il pannello diagnostico sincrono resta bloccante nella prova senza uscita; questo helper è una possibile alternativa da studiare, non un collegamento già pronto per la GUI.

Nel [banco con servizi fixture](../Risultati/GUI_S33/iris_async_helper_cpu_20261030T153515Z/) sette casi esercitano il codice originale: guardia di generazione iniziale negativa; indice già impostato con seconda guardia positiva o negativa; guardia di occupazione negativa; richiesta accettata o rifiutata; e cambio inverso. Per i tre casi con richiesta, la fixture riceve handle `0x1234`, indice richiesto 1 o 9, **wait=0** e timeout `0x3A98`. Quando la fixture accetta, l'helper scrive subito il byte software dello stato e ritorna 1; quando rifiuta, esegue la fixture di cleanup e ritorna 0 lasciando lo stato precedente. Se l'indice è già selezionato e la seconda guardia riesce, richiede il rilascio della risorsa e ritorna 1 senza inoltrare una richiesta.

Nel [secondo banco](../Risultati/GUI_S33/iris_async_real_request_cpu_20261030T153515Z/) la richiesta `0x235B0C` e i due rami di attuazione sono originali, con MMIO inerte e servizi sostituiti. Nei casi 9→1 e 1→9 non occupati, la richiesta passa alla fixture di post l'handler `0x235AE4` con timeout `0x3A98`; la traccia non entra nella funzione di attesa `0x158D04`. Il byte software passa rispettivamente a 1 o 9, mentre i registri sintetici passano da `A5A7/A5B8` a `A5A4/A5B0` oppure `A5A4/A5A8`. Nel caso occupato, stato e MMIO restano invariati, compare il byte sintetico `0x15` e viene chiamata la fixture cleanup. Tutti e tre i casi preservano lo stack; i post sono accettati dalla fixture.

Il fatto che l'helper ritorni 1 e aggiorni lo stato software **non prova che il completamento differito sia stato eseguito o che l'ottica sia arrivata in posizione**. `wait=0` e l'assenza del ramo `0x158D04` sono dimostrati nei casi del banco, non garantiscono che le altre chiamate o i lock non possano attendere nel runtime reale.

## Condizioni e limiti

La handle è impostata dal banco; guardia di generazione, occupazione, lock, post, release e cleanup sono fixture. Non è stato eseguito il callback differito né dimostrato il suo consumatore; MMIO e tasti sono sintetici. Non sono provati acquisizione e proprietà della handle, concorrenza AE, mapping fisico degli stati 1/9 a valori f/, scheduler, GUI o scatto. Il manuale descrive due passi e un filtro ND in grandangolo, ma non associa da solo gli stati software a f/ specifici.

[Verificatore ripetibile](../Python_Trace_Scripts/s33_verify_iris_async_helper_cpu.py): senza argomenti esegue i sette casi con request fixture; con `--real-request` esegue i tre casi con request originale. Nessun dispositivo o firmware installato è stato modificato; **NON_INSTALLARE**.
