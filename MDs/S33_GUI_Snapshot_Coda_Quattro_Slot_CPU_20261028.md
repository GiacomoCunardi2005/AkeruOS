# GUI V1.1 — snapshot sintetico, coda e quattro slot, 28 ottobre 2026

Otto casi GNU ARC700 collegano in un'unica sequenza il callback originale `0x1406D0`, il commit `0x16EC38`, il normalizzatore `0x16E6E0`, il confronto dei record `0x16F86C`, il generatore tasti `0x16F72C`, la coda originale e il dispatcher classe `0x15`. È un avanzamento rispetto alla [prova che iniettava direttamente il tasto logico](S33_GUI_Tasti_Logici_Coda_e_Quattro_Slot_CPU_20261028.md).

Il banco inizializza in RAM sintetica il puntatore al commit, la tabella originale a 16 record, i gate e la coppia precedente a zero. Per ciascuno slot inserisce in `0x1406D0` uno snapshot con un solo bit azzerato; il complemento produce il bit corrispondente impostato. Poi inserisce `0xFFFFFFFF`, producendo lo stato zero. I due eventi sono estratti dalla coda; solo il primo viene consegnato esplicitamente al dispatcher.

**Precisazione successiva:** questi snapshot a 32 bit non sono raggiungibili dalla formula del lettore a due halfword, che produce al massimo `0x03FFFFFF`. La prova rimane valida per il callback isolato, ma non dimostra un ingresso ottenibile dai registri. Una [prova successiva](S33_GUI_MMIO_Snapshot_Quattro_Slot_CPU_20261028.md) esegue il lettore con valori modellati raggiungibili e stato precedente coerente.

| Slot sintetico | Bit snapshot azzerato | Tasto logico | Eventi estratti: stato 1 / 0 | Richiesta registrata per stato 1 |
|---:|---:|---:|---|---|
| 0 | 12 | 11 | `0x580` / `0x581` | ISO `0x3F` oppure tempo `0x3E` |
| 1 | 7 | 14 | `0x700` / `0x701` | menu colore originale `0xBB` |
| 2 | 8 | 67 | `0x2180` / `0x2181` | nessuna, destinazione zero nella copia |
| 3 | 13 | 78 | `0x2700` / `0x2701` | impostazioni `0xB7`, argomento 1 |

Le due varianti ISO e tempo sono alternative per lo slot 0, non un sottomenu combinato. Selezione, argomenti, record di coda, ritorno e stack dopo il dispatch sono verificati con assert. La traccia conferma l'esecuzione delle funzioni sopra; finestre, tabella record e risorse considerate sono confrontate con `MainCode.dmp` V1.1. Il test è passato con 19.391 istruzioni nel modello. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_snapshot_queue_four_routes_cpu.py), [casi](../Risultati/GUI_S33/snapshot_queue_four_routes_cpu_20261028T142040Z/cases.json), [trace e manifest](../Risultati/GUI_S33/snapshot_queue_four_routes_cpu_20261028T142040Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/snapshot_queue_four_routes_cpu_20261028T142040Z/fixture_patches.json).

Il monitor e le letture MMIO non sono eseguiti; il valore è iniettato direttamente nel callback. La [relazione statica con le due letture](S33_GUI_Quattro_Slot_Snapshot_e_Coda_20261027.md) resta condizionale, e i bit 12 e 13 sono ciascuno l'OR di due possibili sorgenti. Non sono provati pulsanti fisici, polarità, pressioni simultanee, scheduler o consegna reale al WindowManager. Lista, contesti e gate sono sintetici; lock, filtro, selezione, attributi e apertura sono fixture, e il DSP GNU v7 è sperimentale. Non si osservano display, cattura, persistenza o monocromatico RAW. La destinazione zero non dimostra che il tasto sia disabilitato nella macchina reale. Nessuna operazione su fotocamera o SD. **NON_INSTALLARE**.
