# GUI: due sorgenti per i bit snapshot 12 e 13

Il 29 ottobre 2026 il lettore originale V1.1 `0x2D62D8` è stato eseguito su GNU ARC700 con le due halfword MMIO simulate come memoria ordinaria. Per ciascuno dei bit 12 e 13 dello snapshot, sono state provate tutte le quattro combinazioni dei due bit sorgente, mantenendo a uno gli altri bit delle halfword.

| Sorgente dalla halfword `0x0FE70224` | Sorgente dalla halfword `0x0FE70228` | Bit nello snapshot |
|---:|---:|---:|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 1 |

Per il bit snapshot 12 le sorgenti sono rispettivamente bit 2 e bit 12; per il bit 13 sono bit 3 e bit 13. Entrambe le tabelle sono quindi OR: azzerare una sola sorgente non cambia lo snapshot quando l'altra resta a uno. Il risultato conferma con esecuzione CPU la formula già identificata staticamente e spiega perché la [prova precedente di coda e quattro slot](S33_GUI_MMIO_Snapshot_Quattro_Slot_CPU_20261028.md) doveva azzerare entrambe le sorgenti per ottenere `0x580` o `0x2700` nelle sue condizioni iniziali.

Otto casi PASS, 215 istruzioni: [verificatore](../Python_Trace_Scripts/s33_verify_gui_snapshot_or_sources_cpu.py), [valori](../Risultati/GUI_S33/snapshot_or_sources_cpu_20261029T054447Z/cases.json), [traccia e manifest](../Risultati/GUI_S33/snapshot_or_sources_cpu_20261029T054447Z/verified_evidence.json). La finestra del lettore è confrontata con il dump originale; gli input sono sintetici e sono mantenuti stabili fra le letture.

Questa prova esegue il solo lettore, non il monitor, il callback o la coda. Non dimostra che le sorgenti siano pulsanti distinti, la polarità elettrica, il loro ordine fisico, l'atomicità o i valori reali MMIO. Gli eventi sono una relazione ricavata dalle prove precedenti, non generati in questi otto casi. Nessuna operazione su fotocamera o SD; **NON_INSTALLARE**.
