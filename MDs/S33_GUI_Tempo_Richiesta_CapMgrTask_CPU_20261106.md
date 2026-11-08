# Menu tempo, richiesta e CapMgrTask — 6 novembre 2026

**7/7 CPU emulata PASS; NON_INSTALLARE.** Dopo la conferma del tempo e la registrazione di `0xDB138` nel contesto come nella [prova precedente](S33_GUI_Tempo_CapMgrTask_CPU_20261106.md), il banco chiama la routine originale `0x14A968`. Questa imposta lo stato 5, cancella il bit evento `0x8`, segnala `0x1` e attende `0x8`. Una fixture cooperativa, durante tale attesa, richiama `CapMgrTask` `0x14A4C4`: il task osserva `0x1`, sceglie lo stato 5 e chiama indirettamente `DB138 → DB33C → D8CA4 → FDA28`. Il task esegue la notifica originale di `0x8` a `0x14A596`; la fixture conclude il task e riprende la richiesta, che osserva `0x8` e ritorna zero.

| Tempo confermato | Limite sintetico | Risultato software | Caso | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | base | `snapshot_capture_focus_original_cpu_20261106T090323514383Z_251057` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261106T090323513874Z_251058` |
| 121 | 20000 | 20000 | limite | `snapshot_capture_focus_original_cpu_20261106T090323473053Z_251059` |
| 119 | 20000 | 20000 | discesa e limite | `snapshot_capture_focus_original_cpu_20261106T090323521987Z_251060` |
| 121 | 1000000 | 121000 | ritorno menu libero | `snapshot_capture_focus_original_cpu_20261106T090323523961Z_251061` |
| 121 | 1000000 | 121000 | retry menu iniettato | `snapshot_capture_focus_original_cpu_20261106T090323525589Z_251062` |
| 121 | 1000000 | 121000 | notifica `0x8` soppressa dalla fixture | `snapshot_capture_focus_original_cpu_20261106T090323524614Z_251063` |

Nel settimo caso la fixture non memorizza `0x8`, restituisce errore 1 all'attesa e la richiesta originale salta la lettura del risultato e ritorna 1. Il calcolo era già avvenuto; questa prova descrive l'errore del modello, non un timeout hardware. ISO 125 e flag 1 sono sintetici. Regressione del banco precedente senza richiesta: `snapshot_capture_focus_original_cpu_20261106T090323481078Z_251064` PASS. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py).

La sequenza è imposta: il banco invoca direttamente la richiesta; la fixture realizza un cambio di contesto cooperativo annidato, non una schedulazione concorrente reale. Attesa, segnalazione, sincronizzazione, RAM, MMIO e numerosi servizi sono modellati. La funzione DB138 è ancora interrotta dopo il calcolo a `0xDB340`; il task è terminato artificialmente dopo la notifica a `0x14A59A`. Pertanto il risultato di ritorno non rappresenta la funzione originale completa. DSP GNU sperimentale. Non si dimostrano attivazione da tasto, tempo fisico, AE, persistenza o sensore; nessuna operazione su fotocamera o supporti.
