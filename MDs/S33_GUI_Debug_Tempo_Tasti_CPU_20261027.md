# S33 — navigazione diagnostica del valore tempo

Il 27 ottobre 2026 ho eseguito in GNU ARC700 gli handler originali V1.1 della schermata interna `DebugModeExpTime` e la routine originale che normalizza il valore. La tabella eventi collega `0x0380` a `0x7D23C8` e `0x0400` a `0x7D241C`; i comandi diagnostici associano separatamente i codici iniziali a Up e Down. Questo non prova il recapito né l'identità fisica dei pulsanti.

La word di lavoro è `0x899AD0`. In sei scenari con valore e contesto sintetici:

| Evento iniettato direttamente | Valore iniziale → finale |
| --- | --- |
| `0x0380` | 0 → 120; 120 → 121; 3999 → 0 |
| `0x0400` | 0 → 119; 2 → 1; 1 → 0 |

La routine scrive anche un byte di direzione e richiede un timer, qui sostituito da una fixture. La normalizzazione originale viene eseguita; le routine di formato, risorsa, testo, aggiornamento e timer sono cinque fixture. La prova non esegue la ripetizione del timer. Il significato dei numeri in unità fisiche, il display reale e l'applicazione allo scatto non sono dimostrati.

Questa prova completa il collegamento **condizionale e offline** fra gli eventi delle due voci e la word di lavoro; la [prova della conferma](S33_GUI_Debug_Valori_ISO_Tempo_CPU_20261027.md) esegue separatamente il callback che legge quella word, la moltiplica per 1000 e la inoltra ai setter. Le due prove non dimostrano una sessione GUI continua o la persistenza contro l'AE.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_exptime_navigation_cpu.py), [sei casi PASS](../Risultati/GUI_S33/debug_time_navigation_cpu_20261027T214034Z/cases.json), [fixture](../Risultati/GUI_S33/debug_time_navigation_cpu_20261027T214034Z/fixture_patches.json), [disassemblato](../Risultati/GUI_S33/debug_time_navigation_cpu_20261027T214034Z/gnu_windows.txt) e [traccia](../Risultati/GUI_S33/debug_time_navigation_cpu_20261027T214034Z/cases.trace). Il primo tentativo `debug_time_navigation_cpu_20261027T214030Z` è FAIL perché mancava nella mappa di laboratorio il payload contenente un servizio fixture; nessuna istruzione originale è stata modificata per aggirare limiti dell'emulatore. Nessun hardware o SD; candidati **NON_INSTALLARE**.
