# S33 — confronto degli eventi live view `0x700` e `0x2180`

Il 30 ottobre 2026 ho esteso il [banco del wrapper live view](../Python_Trace_Scripts/s33_verify_gui_liveview_slot2_wrapper.py): negli stessi contesti e con le stesse fixture confronta gli eventi `0x700` e `0x2180`, inseriti direttamente nel wrapper originale V1.1 `0x6524F4`. La tabella originale `0x7833EC` associa rispettivamente i callback `0x65426C` e `0x655F34`; entrambi sono eseguiti. I byte di tabella e finestre sono confrontati con `MainCode.dmp`.

| Modalità sintetica, guardie inattive | `0x700` | `0x2180` |
|---|---|---|
| `0x0A` | richiede oggetto 2, `CaptureMenu` | richiede oggetto 7, `ShootingMode` |
| `0x46` | richiede oggetto 2, `CaptureMenu` | richiede oggetto 7, `ShootingMode` |
| `0x38`, stato 7 | nessuna richiesta | nessuna richiesta |

Il filtro sintetico contenente l'evento corrispondente blocca la richiesta in entrambi i casi provati. I 9 casi preesistenti su `0x2180` e 4 nuovi casi su `0x700` sono **PASS**, con stack conservato. La fixture `0x1453E4` registra la richiesta ma non apre la schermata. [Casi](../Risultati/GUI_S33/liveview_slot2_wrapper_20261030T154736Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/liveview_slot2_wrapper_20261030T154736Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/liveview_slot2_wrapper_20261030T154736Z/fixture_patches.json). Il primo tentativo `154715Z` è fallito durante il disassemblaggio di una finestra troppo estesa; nessun caso CPU era stato eseguito in quel tentativo.

Il risultato conferma nel medesimo banco che in live view la destinazione dipende dall'evento; non risolve quale evento produca ciascun tasto fisico. Il manuale attribuisce al terzo pulsante la voce «More picture options», ma l'evento `0x2180` iniettato qui non è una pressione fisica. La somiglianza fra il menu del manuale e il `CaptureMenu` resta un'indicazione condizionale, non una mappa elettrica. Lo stato, il filtro e i servizi sono sintetici; coda, scheduler, rendering e hardware non sono osservati. Nessun firmware o dispositivo modificato; **NON_INSTALLARE**.
