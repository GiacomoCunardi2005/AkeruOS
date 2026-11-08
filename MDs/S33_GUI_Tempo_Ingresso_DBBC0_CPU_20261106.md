# Tempo del menu e ingresso del consumatore DBBC0 — 6 novembre 2026

**7/7 CPU emulata PASS; NON_INSTALLARE.** Dopo il percorso menu/calcolo modellato come nella [prova precedente](S33_GUI_Tempo_Copia_Consumatore_Acquisizione_CPU_20261106.md), il banco chiama direttamente `0xDBBC0` con un argomento sintetico. La routine originale crea il frame ed esegue il percorso fino alla copia di 240 byte a `0xDBCBC`; una fixture a `0xDBCD2` salva la copia e termina la prova ripristinando lo stack. Il banco confronta tutti i byte con la sorgente `0x380844`, controlla i canarini e verifica tempo, ISO e flag.

| Modo sintetico | Tempo scelto | Limite | Tempo copiato | Caso | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---:|---|---|
| 4 | 121 | 1000000 | 121000 | normale | `snapshot_capture_focus_original_cpu_20261106T091755200087Z_281800` |
| 4 | 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261106T091755204073Z_281801` |
| 4 | 121 | 20000 | 20000 | limite | `snapshot_capture_focus_original_cpu_20261106T091755175647Z_281803` |
| `0x42` | 121 | 1000000 | 121000 | normale | `snapshot_capture_focus_original_cpu_20261106T091755204075Z_281802` |
| `0x42` | 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261106T091755212390Z_281804` |
| `0x42` | 121 | 20000 | 20000 | limite | `snapshot_capture_focus_original_cpu_20261106T091755165093Z_281805` |
| `0x42` | 121 | 1000000 | 121000 | notifica soppressa nel modello | `snapshot_capture_focus_original_cpu_20261106T091755202387Z_281806` |

ISO 125 e flag 1 sono sintetici. Con modo `0x42` e byte `0x37FD76=1`, il codice esegue anche la copia originale di 124 byte verso `0x3792CC`; il banco verifica che corrisponda ai primi 124 byte del buffer copiato. Con modo 4, il confronto `0xDBC52` salta direttamente alla copia da 240 byte. Il banco imposta il modo `0x42` **dopo** il calcolo; non si deduce che la fotocamera esegua questa transizione. L'ultimo caso invoca `DBBC0` anche dopo l'errore di attesa modellato, senza inferire che ciò avvenga sulla camera.

Regressione con ingresso diretto nel frammento `0xDBCBC`: `snapshot_capture_focus_original_cpu_20261106T091805090733Z_286061` PASS. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py).

`0x149890` è una fixture che permette il percorso e `0xDBB90` una fixture; sono attive anche copia byte, getter di dati, eventi e altre fixture precedenti. Il ramo modo `0x42` con byte diverso da 1 può ricalcolare e sovrascrivere l'area, ma non è eseguito qui. La callback candidata `0x1BA9C4` e la continuazione di `DBBC0` dopo `0xDBCD2` non sono eseguite. Non sono dimostrati ordine reale di scatto, S2, sensore, AE, persistenza o unità fisiche; DSP GNU sperimentale. Nessuna operazione su camera o supporti.
