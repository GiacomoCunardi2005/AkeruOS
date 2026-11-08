# Menu tempo e ritorno originale DB138 — 6 novembre 2026

**7/7 CPU emulata PASS; NON_INSTALLARE.** Nel [banco cooperativo precedente](S33_GUI_Tempo_Richiesta_CapMgrTask_CPU_20261106.md) la routine `0xDB138` si fermava alla prima chiamata al calcolo. Ora il banco lascia eseguire la continuazione originale e il suo epilogo `0xDB796..0xDB7A0`, fino al ritorno nel task `0x14A592`. Nel percorso sintetico selezionato, la funzione chiama `0xD8CA4` due volte, da `0xDB33C` e `0xDB666`. Il registratore conserva separatamente entrambi i risultati; il banco controlla anche la copia finale, il valore restituito, la notifica e lo stack.

| Tempo confermato | Limite sintetico | Tempo nei due risultati e nella copia finale | Caso | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | base | `snapshot_capture_focus_original_cpu_20261106T090703570850Z_258545` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261106T090703573438Z_258546` |
| 121 | 20000 | 20000 | limite | `snapshot_capture_focus_original_cpu_20261106T090703570850Z_258544` |
| 119 | 20000 | 20000 | discesa e limite | `snapshot_capture_focus_original_cpu_20261106T090703581020Z_258548` |
| 121 | 1000000 | 121000 | ritorno menu libero | `snapshot_capture_focus_original_cpu_20261106T090703552585Z_258547` |
| 121 | 1000000 | 121000 | retry menu iniettato | `snapshot_capture_focus_original_cpu_20261106T090703535618Z_258549` |
| 121 | 1000000 | 121000 | notifica soppressa dal modello | `snapshot_capture_focus_original_cpu_20261106T090703551837Z_258550` |

Entrambi i risultati hanno ISO sintetico 125 e flag 1. Nei primi sei casi la richiesta ritorna zero; nel settimo la fixture dell'attesa ritorna 1 e la richiesta propaga 1. Regressione del banco precedente con continuazione intercettata: `snapshot_capture_focus_original_cpu_20261106T090703576200Z_258551` PASS. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py).

La seconda chiamata ha esposto un errore nella fixture del registratore `0xD8E22`: per `r16=1` essa saltava a `0xD8E28`, sovrascritto dagli ultimi due byte del trampolino, causando un ciclo. I due tentativi falliti sono conservati. La fixture ora riproduce la chiamata originale a `0xDEB30` e riprende a `0xD8E2C`; in questa prova `0xDEB30` è una fixture che ritorna zero. Le prove precedenti usavano `r16=0` e non attraversavano il ramo difettoso. Entrambi i rami attraversati sono controllati dalle tracce della nuova matrice.

Il banco richiama esplicitamente la richiesta; sincronizzazione/eventi e cambio di contesto sono modellati cooperativamente. Tra le nuove fixture, `0xE12A4` ritorna 1, altri servizi della continuazione ritornano zero; le altre fixture e il registratore che riproduce il confronto restano attive. Il task viene fermato artificialmente dopo la notifica, mentre `DB138` è arrivata al proprio ritorno originale. I risultati valgono soltanto per questi ingressi, rami e modello DSP GNU sperimentale. Non sono dimostrati tasto fisico, sensore, AE, persistenza, concorrenza o unità fisiche; nessuna operazione su camera o supporti.
