# S33 — timer del monitor dei tasti: Ghidra e prova CPU

31 ottobre 2026, firmware V1.1. Nel ramo bit 9 il monitor originale chiede al servizio `0x145BF4` un timer con argomenti `0x2420B4, 0, 1, 0x3A98, 0x36A6C8`; un registratore fixture li osserva nell'ultima chiamata di ciascun run. Non sono state determinate le unità temporali né la semantica completa del servizio.

Il [C esportato da Ghidra con estensione ARCompact](../Ghidra_Results/ARCompact_Test/esteso/main_tbm/c/00145bf4.c) suggerisce che `145BF4` inoltri quattro argomenti e scriva un risultato tramite puntatore. I nomi `extraout_r2`, `extraout_r3`, `extraout_r4` sono artefatti del decompilatore: il [disassemblaggio GNU](../Risultati/GUI_S33/ghidra_monitor_20261031/gnu_windows.txt) mostra che r0–r4 sono salvati all'ingresso e r4 è il puntatore di destinazione. Il C non è sorgente originale e non prova l'ABI o il timer completo. Il C di `0x145C2C` chiama due routine, ma la loro semantica effettiva non è dimostrata da questa analisi.

Il pool V1.1 e il disassemblaggio indicano `0x2420B4` come callback programmato, non il produttore `0x242040` che notifica i bit 8/9. Il callback chiama `0x145C2C`, azzera `0x36A6C8`, incrementa `[0x5545F8+0x3C]` e chiama `0x242094`, che imposta il modo 1 e chiama i servizi di disabilitazione, pulizia e riabilitazione monitor. Quei servizi rimangono fixture nella prova: non si può escludere che l'hardware generi successivamente altri eventi.

## Esecuzione controllata

Il [banco esistente](../Python_Trace_Scripts/s33_verify_gui_monitor_rearm_four_routes_cpu.py) è stato esteso con `--timeout`, sui quattro slot e due destinazioni sintetiche ISO/tempo. Dopo il bit 8 iniziale e la maschera `0x300`, il banco inserisce nella cella timer il valore sintetico `0x1234` e chiama direttamente `0x2420B4`, con servizio di cancellazione fixture. Osserva modo 2→1, contatore callback 0→1 e cella timer→0. Successivamente forza un bit 8: il contatore dei fallimenti diventa 2 e la coda è vuota. Forza poi bit 9 e bit 8: il riarmo avviene e il rilascio logico atteso è estratto.

| Esecuzione | Sequenze | Esito |
|---|---:|---|
| Callback imposto dopo `0x300` | 8 | [PASS](../Risultati/GUI_S33/monitor_timeout_four_routes_cpu_20261031T153851Z/verified_evidence.json) |
| `0x300`, senza callback imposto | 8 | [PASS](../Risultati/GUI_S33/monitor_combined_four_routes_cpu_20261031T153851Z/verified_evidence.json) |
| Bit 9 separato, senza callback imposto | 8 | [PASS](../Risultati/GUI_S33/monitor_rearm_four_routes_cpu_20261031T153851Z/verified_evidence.json) |

Ogni run include anche tre controlli negativi. Gli input iniziali, le destinazioni e le due coppie MMIO sono sintetici; il timer non viene eseguito da uno scheduler, e il valore `0x1234` non è un handle osservato sulla camera. Sono controllati finestre e pool del codice originale rispetto al dump, traccia dell'ingresso callback, stato, coda e stack. La prova non dimostra quale ordine temporale avvenga sulla fotocamera né una perdita reale di rilascio.

## Limiti di Ghidra

Il C aggregato già disponibile non contiene ingressi separati per `0x242040`, `0x242094`, `0x2420B4` o `0x242104`. Un tentativo di generare un'esportazione mirata su copia del progetto ha fallito: Ghidra non ha caricato il bundle dello script Java; il processo headless ha comunque restituito 0. I [log](../Risultati/GUI_S33/ghidra_monitor_20261031/headless_scripts.log) conservano l'errore e **non** costituiscono un nuovo decompilato. Gli indirizzi del callback e i suoi effetti sono stati quindi controllati con GNU e prova CPU, non attribuiti al C Ghidra. La copia del progetto è isolata; firmware e fotocamera invariati. **NON_INSTALLARE**.

Successivamente l'[esportazione mirata PyGhidra](../Risultati/GUI_S33/ghidra_monitor_20261031/decompiled.c) è riuscita su copia isolata. [Rapporto successivo](S33_GUI_Esposizione_Ghidra_Ritorno_Copia_20261031.md): il C è ausilio di analisi e non prova semantica completa.
