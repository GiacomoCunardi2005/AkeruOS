# S33 — monitor con eventi combinati, 31 ottobre 2026

Nel firmware V1.1 il monitor `0x242104` verifica il bit 8 prima del bit 9, poi il bit 10. Questo ordine emerge dal disassemblaggio originale; la prova qui copre **solo bit 8 e 9**, con dati sintetici e bit 10 assente. La motivazione è verificare cosa accade se la notifica del confronto e quella di riarmo arrivano nella stessa chiamata, anziché nelle due chiamate separate della [prova precedente](S33_GUI_Monitor_Riarmo_Quattro_Slot_CPU_20261028.md).

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_monitor_rearm_four_routes_cpu.py) ora accetta `--combined`. In entrambi i run, quattro slot e due destinazioni alternative ISO/tempo: la prima chiamata con bit 8 produce l'evento di stato 1; il monitor passa a modo 1. Il banco modifica confronto e snapshot, da un valore con un bit azzerato a `0x03FFFFFF`. Il solo cambiamento tra i run è la maschera della chiamata intermedia, `0x200` o `0x300`; la chiamata finale `0x100` è identica.

| Maschera intermedia | Tentativi falliti dopo chiamata | Modo e target dopo chiamata | Coda prima dell'ultimo bit 8 | Evento dopo ultimo bit 8 |
|---|---:|---|---|---|
| `0x200` | 0 | 2, `0x03FFFFFF` | vuota | stato 0 |
| `0x300` | 1 | 2, `0x03FFFFFF` | vuota | stato 0 |

In entrambi i casi, prima dell'ultimo bit 8, snapshot e contatore dei successi restano quelli della prima consegna. Nel caso combinato il ramo bit 8 incontra modo 1 e confronto diverso dal vecchio target, incrementa il contatore di fallimento; il ramo bit 9 successivo imposta target e modo 2. Il test non attribuisce il fallimento a una sola guardia. Il successivo bit 8 consegna lo snapshot ripristinato e produce il rilascio atteso. I tre controlli indipendenti preesistenti verificano anche mismatch con modo 2, modo 1 con confronto uguale e callback nullo.

Otto sequenze e tre controlli per run PASS: [combinato](../Risultati/GUI_S33/monitor_combined_four_routes_cpu_20261031T153722Z/verified_evidence.json), [separato](../Risultati/GUI_S33/monitor_rearm_four_routes_cpu_20261031T153722Z/verified_evidence.json). Il banco controlla anche coda vuota intermedia, target, modo, contatori, snapshot, eventi e stack. Le finestre del percorso sono confrontate con `MainCode.dmp`; il DSP GNU v7 è sperimentale.

**Limiti:** il banco impone maschere, ordine, valori MMIO e callback; timer, filtri, sincronizzazione e servizi GUI sono fixture. La prova non stabilisce che i bit arrivino combinati sulla camera, che il timer reale produca il successivo bit 8, o che un rilascio fisico venga consegnato. Lo scheduler e la mappa fisica dei tasti non sono eseguiti. Non si può dedurre perdita reale di un evento. Nessuna operazione su fotocamera o SD; **NON_INSTALLARE**.

La [prova successiva del callback timer](S33_GUI_Timer_Monitor_Ghidra_CPU_20261031.md) mostra che, quando il banco lo invoca prima del successivo bit 8, il monitor torna a modo 1; un nuovo bit 9 imposto dal banco lo riarma. Il timer reale e la generazione degli eventi restano fuori dalla prova.
