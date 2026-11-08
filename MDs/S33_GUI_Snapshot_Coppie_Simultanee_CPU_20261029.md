# GUI: coppie simultanee nello snapshot sintetico

Il 29 ottobre 2026 ho esteso la [prova dei quattro slot con lettore e coda](S33_GUI_MMIO_Snapshot_Quattro_Slot_CPU_20261028.md) alle sei coppie di bit snapshot 12, 7, 8 e 13. Il banco predispone insieme i due bit di ogni coppia tramite le halfword sintetiche, esegue lettore originale `0x2D62D8`, callback `0x1406D0`, normalizzatore, generatore e coda; estrae due volte, poi ripristina entrambe le halfword e tenta altre due estrazioni. Le prove non consegnano gli eventi a una finestra.

| Slot logici sintetici, numerati 1–4 | Eventi estratti dopo attivazione, poi ripristino |
|---|---|
| 1 + 2 | `580`, `700`, `581`, `701` |
| 1 + 3 | `580`, `2180`, `581`, `2181` |
| 1 + 4 | nessuno nelle quattro estrazioni |
| 2 + 3 | nessuno nelle quattro estrazioni |
| 2 + 4 | `700`, `2700`, `701`, `2701` |
| 3 + 4 | `2180`, `2700`, `2181`, `2701` |

Le sei coppie sono state ripetute in ordine inverso: 12 casi PASS, 28.874 istruzioni, con verifica snapshot, record, ritorno estrazione e stack. I casi condividono il backing, ma il banco reimposta stato precedente e gate selezionati; l'ordine inverso riduce un possibile effetto della sequenza, senza dimostrare indipendenza completa. [Banco](../Python_Trace_Scripts/s33_verify_gui_mmio_snapshot_pairs_cpu.py), [casi](../Risultati/GUI_S33/mmio_snapshot_pairs_cpu_20261029T054555Z/cases.json), [traccia e manifest](../Risultati/GUI_S33/mmio_snapshot_pairs_cpu_20261029T054555Z/verified_evidence.json). Il primo tentativo `20261029T054531Z` è conservato come FAIL perché assumeva erroneamente quattro eventi per tutte le coppie.

La [successiva correzione del normalizzatore](S33_GUI_Normalizzatore_Gruppi_Correzione_CPU_20261029.md) spiega la differenza: con gate zero il limite è di un bit per ciascun gruppo separato, non per tutti i bit insieme. Un banco isolato ha verificato tutte le 16 combinazioni dei quattro bit con gate 0 e 1. Le conclusioni restano limitate ai contesti sintetici testati.

La simultaneità riguarda valori predisposti dal banco e letti sequenzialmente da celle MMIO ordinarie; callback, tabella, gate e stato iniziale sono predisposti, lock/filtro/notifica sono fixture e DSP è sperimentale. Non sono provati tasti o livelli fisici, atomicità, rimbalzo, scheduler, consegna alla GUI, scatto o comportamento su camera. Nessuna modifica a firmware o SD; **NON_INSTALLARE**.
