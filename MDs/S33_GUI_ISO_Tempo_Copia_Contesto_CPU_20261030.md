# GUI — copia del contesto ISO e tempo, prova CPU

Il 30 ottobre 2026 ho eseguito in GNU ARC700 i setter diagnostici originali `0xD03B8` e `0xD03E0`, poi la funzione originale di copia `0xF6F54` e il suo helper `0xAD920`. Lo scopo è verificare il collegamento precedentemente dedotto staticamente fra i valori modificati e una copia del contesto usata da un calcolo. RAM, contenuto iniziale e sequenza delle chiamate sono sintetici.

Per ogni caso il banco inizializza i 64 byte sorgente, chiama i setter, salva separatamente i 64 byte risultanti e chiama `0xF6F54` su una destinazione di laboratorio. Dopo il ritorno cambia nuovamente ISO e tempo con i setter originali e confronta i campi correnti con quelli della copia:

| Indice ISO iniziale → valore software | Tempo software iniziale | Nuovo indice → valore software | Nuovo tempo software |
|---|---:|---|---:|
| 6 → 125 | 42.000 | 19 → 1.600 | 121.000 |
| 0 → 0 | 0 | 6 → 125 | 1.000 |
| 19 → 1.600 | 4.000.000 | 0 → 0 | 0 |

In tutti e tre i casi la copia contiene **esattamente i 64 byte** presenti prima della chiamata, compresi ISO a `+0x22` e tempo a `+0x24`; la successiva modifica della sorgente non altera la copia. La traccia mostra il flag software a `0x380A35` scritto a 1 prima di `0xAD920` e a 0 dopo, e il banco verifica il valore finale zero e lo stack. Il test non esercita concorrenza, dunque il flag non dimostra atomicità o sincronizzazione fra task.

Il chiamante `0xD8CA4` e la successiva routine `0xFDA28` sono collegati **staticamente**, non eseguiti da questa prova: [analisi precedente](S33_GUI_Tempo_Ingresso_Calcolo_20261027.md). Le prove non dimostrano che la copia sia usata dopo una scelta reale, che sopravviva a AE, o che imposti guadagno/tempo del sensore. L'unità fisica del tempo rimane ignota; il valore numerico ISO non è una misura di sensibilità. La prova usa i setter direttamente, senza menu, coda o fotocamera.

[Verificatore ripetibile](../Python_Trace_Scripts/s33_verify_gui_exposure_context_snapshot_cpu.py), [casi](../Risultati/GUI_S33/exposure_context_snapshot_cpu_20261030T101322Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/exposure_context_snapshot_cpu_20261030T101322Z/verified_evidence.json). Il primo tentativo `101313Z` è fallito all'assemblaggio per operandi di store; il secondo `101316Z` ha superato i confronti dei dati ma fallito un controllo dei prefissi di traccia con zero iniziale. Il banco finale corregge entrambi. Firmware e dispositivo non modificati; **NON_INSTALLARE**.
