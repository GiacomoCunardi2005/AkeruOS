# GUI V1.1 — monitor, snapshot e quattro slot, 28 ottobre 2026

Il monitor originale `0x242104`, invocato con il bit 8, esegue in otto sequenze GNU ARC700 il confronto tramite `0x2D62B0`, richiama `0x2B7190` e il lettore snapshot `0x2D62D8`, quindi invoca indirettamente il callback `0x1406D0` dal campo `0x5545F8+0x18`. Da lì le istruzioni originali generano gli eventi, li inseriscono nella coda e il banco consegna il primo evento estratto al dispatcher della classe `0x15`. È una continuazione della [prova del lettore](S33_GUI_MMIO_Snapshot_Quattro_Slot_CPU_20261028.md), che chiamava il callback dal banco.

Per ciascuna delle due varianti ISO/tempo e dei quattro slot, il banco inizializza il confronto a zero, il target a zero, il modo monitor a 2 e il callback a `0x1406D0`; imposta i valori delle due halfword snapshot come nel rapporto precedente. Il primo passaggio produce rispettivamente `0x580`, `0x700`, `0x2180` o `0x2700`; dopo il ripristino delle halfword, un secondo passaggio produce l'evento con bit 0 impostato. **Il banco riporta il modo a 2 prima del secondo passaggio:** il percorso originale di conclusione `0x242094` lo aveva posto a 1. La selezione e le richieste sono verificate come nella prova precedente; ISO e tempo sono destinazioni alternative e il terzo slot ha destinazione zero nella lista sintetica.

Tre controlli aggiuntivi partono con stato separato e verificano contatori, snapshot e word bassa della coppia precedente:

| Condizione | Contatore mancato / riuscito | Snapshot dopo il monitor | Word bassa della coppia |
|---|---|---|---|
| Target diverso dalla lettura | 1 / 0 | sentinella `0x12345678` invariata | `0xFC000000` invariata |
| Modo diverso da 2 | 1 / 0 | sentinella invariata | `0xFC000000` invariata |
| Callback nullo, confronto e modo validi | 0 / 1 | `0x03FFFFFF` aggiornato | `0xFC000000` invariata |

Nel caso con callback nullo l'aggiornamento dello snapshot e l'incremento del contatore di successo precedono il controllo del puntatore: non equivalgono alla consegna dell'evento. I tre controlli non verificano separatamente la coda.

PASS su 22.221 istruzioni nel modello; assert su snapshot, due record di coda, selezione, argomenti, stack dopo dispatch e controlli aggiuntivi. Finestre e dati esaminati sono confrontati con `MainCode.dmp` V1.1; DSP GNU v7 sperimentale. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_monitor_snapshot_four_routes_cpu.py), [manifest e traccia](../Risultati/GUI_S33/monitor_snapshot_four_routes_cpu_20261028T142321Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/monitor_snapshot_four_routes_cpu_20261028T142321Z/fixture_patches.json). Primo tentativo `20261028T142254Z` fallito per lettura MMIO non mappata durante il cleanup; successiva prova `20261028T142305Z` usa fixture esplicite per i servizi di controllo e pulizia, mantenute nella prova finale.

Il banco invoca direttamente il monitor e installa il puntatore callback: task, evento kernel, registrazione e riarmo reali non sono eseguiti. Entrambe le coppie di registri sono memoria ordinaria sintetica; `0x2D627C`, `0x2D61CC`, `0x2B71F0`, `0x2D6198`, lock, filtri e servizi GUI sono fixture. La condizione iniziale e i livelli non sono osservazioni hardware. Nessuna prova di pulsanti fisici, atomicità, display, cattura, persistenza o RAW; **NON_INSTALLARE**.
