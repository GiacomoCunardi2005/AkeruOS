# S33 — scelte ISO e ripristino AutoScene, matrice CPU

Il 31 ottobre 2026 ho ampliato il [confronto precedente](S33_GUI_ISO_Autoscene_Ripristino_Calcolo_CPU_20261030.md) con cinque scelte della lista diagnostica, due byte di modalità sintetici e assenza/presenza di un aggiornamento operativo imposto: **20 casi GNU ARC700 DSP sperimentale PASS**. Il [comando unico](../Python_Trace_Scripts/s33_check_iso_autoscene_matrix.py) salva per ogni caso log e percorso del manifest; [riepilogo](../Risultati/GUI_S33/iso_autoscene_matrix_20261031T154827849530Z/summary.json).

Ogni prova parte con ISO software 1600, conferma una scelta, imposta il tempo diagnostico a 42.000, eventualmente chiama il setter operativo con indice 19/1600, poi entra nel frammento originale `0x659C08`. Per modo sintetico `0x2C` è eseguito il percorso `0x65BA94 → 0x65BC60 → 0xCA654`; per `0x2B` esso viene saltato. Il banco chiama successivamente il calcolo `0xD8CA4` e legge ISO nella copia finale.

| Scelta diagnostica | Conferma senza aggiornamento successivo, entrambi i modi | Con aggiornamento a 1600, modo `0x2C` | Con aggiornamento a 1600, modo `0x2B` |
|---|---:|---:|---:|
| Exit | 1600 | 1600 | 1600 |
| ISO 50 | 50 | 50 | 1600 |
| ISO 120 | 120 | 120 | 1600 |
| ISO 1600 | 1600 | 1600 | 1600 |
| ISO 3200 | 3200 | 3200 | 1600 |

Le cifre sono **valori software**, non misure della sensibilità. Exit parte già da 1600 e l'aggiornamento imposto scrive anch'esso 1600: questi quattro casi non distinguono eventuali alterazioni con altri valori iniziali. Anche per la scelta 1600 l'aggiornamento imposto è dello stesso valore; l'effetto differenziale si osserva per 50, 120 e 3200. Le scelte Auto e 125 restano coperte dagli otto casi del rapporto precedente, non ripetuti in questa matrice.

Il [C Ghidra](../Risultati/GUI_S33/ghidra_monitor_20261031/exposure.c) e le istruzioni GNU del percorso `0xCA654` sono coerenti con la sostituzione condizionale dell'indice diagnostico nonzero nel record prima del setter operativo. Il C ha limiti noti; la prova CPU controlla anche record, buffer finale, numero di chiamate e stack, con le fixture elencate in ogni manifest. Modalità, tasto, scelta, modifica operativa e ordine sono imposti; il banco entra in un frammento, non nell'handler completo, e chiama il calcolo esplicitamente. Non dimostra che la camera segua quell'ordine, che AE agisca così o che ISO/tempo siano applicati al sensore. L'unità fisica del tempo resta sconosciuta; **NON_INSTALLARE**.
