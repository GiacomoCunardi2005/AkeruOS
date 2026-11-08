# GUI V1.1 — ramo AutoScene e ripristino tempo, 28 ottobre 2026

Otto sequenze GNU ARC700 eseguono il frammento originale `0x659C08`: il banco imposta `r14` al getter originale `0xCAD30`, il quale legge un byte di modalità sintetico; il confronto e la chiamata condizionale al wrapper `0x65BA94` sono originali. Il banco entra direttamente nel frammento e intercetta la continuazione `0x659C12` con una fixture di uscita: non esegue l'intero handler `0x65959C`.

Dopo la conferma diagnostica 121.000 e ciascuno dei quattro setter artificialmente invocati nella [prova precedente](S33_GUI_Tempo_Wrapper_Ripristino_CPU_20261028.md), vengono confrontati due valori del solo byte modalità:

| Modalità sintetica | Ingressi al wrapper | Campo `0x37FBF4` dopo il ramo |
|---|---:|---|
| `0x2C` | 4 su 4 | 121.000 in tutti i casi |
| `0x2B` | 0 su 4 | invariato rispetto a subito dopo il setter: 0, 1.000.000, 121.000 o 500.000 |

Nel percorso `0x2C`, anche il record temporaneo osservato dalla fixture vale 121.000. Nel percorso `0x2B` non viene osservato un record di ripristino: lo zero nel buffer dei risultati significa che la fixture del record non è stata raggiunta. Assert su otto ingressi al frammento, quattro al wrapper, campi, risultati del setter e stack. PASS: 137.718 istruzioni nel modello; [verificatore](../Python_Trace_Scripts/s33_verify_gui_time_confirm_autoscene_branch_cpu.py), [casi](../Risultati/GUI_S33/time_confirm_autoscene_branch_cpu_20261028T143134Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/time_confirm_autoscene_branch_cpu_20261028T143134Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/time_confirm_autoscene_branch_cpu_20261028T143134Z/fixture_patches.json). Finestre e letterali confrontati col dump V1.1; DSP GNU v7 sperimentale. Il tentativo `143121Z` è conservato come FAIL per un'istruzione non accettata dall'assemblatore nella fixture; le successive esecuzioni usano `j [r19]`.

Il confronto riguarda soltanto `0x2C` e `0x2B`, con ingresso e puntatore predisposti dal banco. Il collegamento dell'evento `0x4405` all'handler è [statico](S33_GUI_Tempo_Autoscene_Collegamento_Statico_CPU_20261028.md); l'arrivo dell'evento e la conservazione di `r14` nei percorsi reali restano da verificare. Servizi di snapshot, GUI e wrapper sono fixture; byte, ordine e registri sono sintetici. Nessuna prova di scatto, unità fisiche o persistenza. **NON_INSTALLARE**.
