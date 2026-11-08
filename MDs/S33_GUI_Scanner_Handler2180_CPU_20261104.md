# Scanner e handler evento 0x2180 — V1.1, CPU emulata, 2026-11-04

Il banco unisce il percorso originale scanner → generatore → fan-out delle due callback → coda → dispatcher → CaptureMenu → lookup condiviso all'handler originale `0x20E940` selezionato dalla pressione `0x2180`. Esegue anche getter di stato, lettura configurazione, costante 42 e resolver di finestra originali. Tutte le finestre originali collegate sono confrontate con i payload verificati dopo il link. **10/10 casi PASS**: due ordini delle callback per ciascuno dei cinque scenari seguenti.

| Scenario imposto | Risultato osservato |
|---|---|
| byte `0x365756 = 2` | uscita prima della query |
| byte `0x365753 = 3` | uscita prima della query |
| query coda simulata restituisce 1 | nessuna richiesta finestra |
| configurazione `[0x61] = 42` | nessuna richiesta finestra |
| guardie aperte, `[0x61] = 41` | notifica stub `0x1564C0(1)`, quattro cancellazioni stub e richiesta stub `0x1453E4(0x87, 0)` |

La query simulata riceve `(0, 0x3101, 0x3101)`. Nell'ultimo caso sono registrate in ordine le cancellazioni `(0, 0x81, 0)`, `(0, 0x80, 0)`, `(0, 0x101, 0)`, `(0, 0x100, 0)`. Pressione/rilascio sono generati dallo scanner con bit 8, classe logica 67 e codici `0x2180`/`0x2181`; gli eventi vengono estratti e inviati esplicitamente dal banco. `0x87` è associato a AutoSceneLiveView nelle analisi precedenti, ma qui la richiesta è intercettata e l'apertura non è eseguita. Non attribuire questa classe a un tasto fisico in assenza di prova.

La finestra CaptureMenu corrente, controllo attivo, stato, configurazione, snapshot, ordine callback e servizi di lock sono fixture; query, cancellazione, notifica e manager finale sono stub. Non sono dimostrati effetti di cancellazione su coda reale, schedulazione, rendering o hardware. La prova usa `0xC9BF8=0`, non generalizzare agli altri gate. I limiti dell'handler isolato e altri rami sono in `MDs/S33_GUI_Notifica_Reattori_Slot_Registro_CPU_20261101.md`. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_key_scanner_handler2180_cpu.py`. Evidenze: `Risultati/GUI_S33/key_scanner_handler2180_cpu_20261104T112352271203Z/verified_evidence.json`. Regressione navigazione ISO: 8/8, `Risultati/GUI_S33/key_scanner_iso_navigation_cpu_20261104T112357613024Z/verified_evidence.json`.
