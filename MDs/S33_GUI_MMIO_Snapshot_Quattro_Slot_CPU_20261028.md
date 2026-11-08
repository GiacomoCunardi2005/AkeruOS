# GUI V1.1 — lettore snapshot e quattro slot, 28 ottobre 2026

Otto sequenze GNU ARC700 eseguono il lettore originale `0x2D62D8` sulle due halfword modellate a `0x0FE70224` e `0x0FE70228`, passano esplicitamente il risultato al callback originale `0x1406D0` e proseguono fino a coda e dispatcher di classe `0x15`. La CPU esegue le due istruzioni `ldh.di` originali; i registri sono celle di memoria ordinaria sintetiche, inizializzate dal banco, non periferiche fisiche.

In ogni caso il banco assume inizialmente le due halfword `0xFFFF` e imposta la coppia precedente normalizzata a `(0xFC000000, 0)`, coerente con lo snapshot `0x03FFFFFF` e la maschera `0xFE31B188`. Il banco sostituisce poi le halfword coi valori indicati, esegue il lettore e passa lo snapshot al callback; ripristina `0xFFFF/0xFFFF` e ripete. Per ogni sequenza verifica entrambi gli snapshot e i due record estratti dalla coda. Il primo evento è consegnato esplicitamente al dispatcher; il secondo è soltanto estratto.

| Slot sintetico | `0x0FE70224` | `0x0FE70228` | Snapshot | Eventi stato 1 / 0 | Richiesta fixture |
|---:|---:|---:|---:|---|---|
| 0 | `0xFFFB` | `0xEFFF` | `0x03FFEFFF` | `0x580` / `0x581` | ISO `0x3F` oppure tempo `0x3E` |
| 1 | `0xFFFF` | `0xFF7F` | `0x03FFFF7F` | `0x700` / `0x701` | colore originale `0xBB` |
| 2 | `0xFFFF` | `0xFEFF` | `0x03FFFEFF` | `0x2180` / `0x2181` | nessuna, destinazione zero |
| 3 | `0xFFF7` | `0xDFFF` | `0x03FFDFFF` | `0x2700` / `0x2701` | impostazioni `0xB7`, argomento 1 |

Per i bit 12 e 13 la formula originale è un OR di due sorgenti: nei casi sopra entrambe sono state azzerate. La necessità di azzerare entrambe segue dalla formula; non è una prova di due interruttori fisici né un test separato delle singole sorgenti. I valori `0xFFFF` sono ipotesi del banco, non livelli reali misurati.

PASS: otto sequenze, 19.807 istruzioni nel modello, controllo di snapshot, eventi, selezione, argomenti e stack dopo il dispatch. Finestre e dati usati sono confrontati con il dump V1.1; il DSP GNU v7 è sperimentale. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_mmio_snapshot_four_routes_cpu.py), [risultati e trace](../Risultati/GUI_S33/mmio_snapshot_four_routes_cpu_20261028T142153Z/verified_evidence.json), [casi](../Risultati/GUI_S33/mmio_snapshot_four_routes_cpu_20261028T142153Z/cases.json) e [fixture](../Risultati/GUI_S33/mmio_snapshot_four_routes_cpu_20261028T142153Z/fixture_patches.json). Il primo tentativo `20261028T142143Z` è fallito prima dell'esecuzione per dimensione insufficiente del file mmap, conservato come FAIL; il secondo ha corretto il padding della fixture.

Il monitor e la registrazione del callback non sono eseguiti: il banco collega esplicitamente lettore e callback. Gate, coppia precedente, lista, sincronizzazione, filtri, selezione e apertura sono sintetici o fixture; ISO e tempo sono destinazioni alternative, non un sottomenu. Non sono provati identità o polarità dei pulsanti, atomicità delle letture, scheduler, GUI fisica, scatto, persistenza o RAW. Nessuna operazione su fotocamera o SD; **NON_INSTALLARE**.
