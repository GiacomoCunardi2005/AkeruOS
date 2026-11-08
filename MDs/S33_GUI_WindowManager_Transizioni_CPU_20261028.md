# S33 V1.1 — transizioni WindowManager con risposte sintetiche

Il 28 ottobre 2026 ho eseguito in GNU ARC700 `0x145180` insieme all'interprete originale `0x14510C` e ai getter originali. I descrittori A e B, la tabella oggetti, lo stato iniziale del gestore e le risposte agli eventi sono sintetici; il dispatcher `0x169D78` e il servizio finale `0x17BF60` sono fixture. Gli indirizzi degli oggetti sono solo indirizzi di laboratorio. Tutti i casi partono **senza schermata precedente**, con flag dei descrittori pari a zero.

| Risposte dei callback simulati | Esito osservato |
| --- | --- |
| A risponde `−2` a `0x4403` e `0x4405` | Dopo i tentativi di risoluzione falliti, il gestore invia ad A `0x4401` con argomento 123 e conclude con A corrente. |
| A risponde `−1` a `0x4403` | Senza precedente non viene trovata una destinazione e la routine ritorna 0 prima di `0x4401`. |
| A risponde `0x00070005` a `0x4403`; B risponde `−2` | L'ID 5 della tabella sintetica risolve B. B riceve `0x4403`, poi `0x4401` con argomento 7, e diventa corrente. |
| A risponde `−2` a `0x4403` e `−1` a `0x4405` | Il gestore aveva impostato A corrente, ma poi invia `0x4406` e `0x4402`, lascia il puntatore corrente nullo e ritorna 0. |

Quattro casi **PASS** verificano ordine degli eventi, risultato, puntatore corrente e stack; il caso di deviazione controlla anche i destinatari e l'argomento. `−2` è un ID signed volutamente non risolvibile in questa tabella: non è una risposta attribuita ai callback reali. I casi non dimostrano una pila di menu, il comportamento di una schermata precedente presente, l'utilizzo effettivo del redirect dai menu diagnostici o il rendering. In particolare non risolvono il ritorno esplicito `(0x36,0)` delle schermate ISO e tempo.

Le finestre eseguite sono confrontate con `DUMPS/MainCode.dmp`. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_window_transition_cpu.py), [casi](../Risultati/GUI_S33/window_transition_cpu_20261028T090634Z/cases.json), [servizi fixture](../Risultati/GUI_S33/window_transition_cpu_20261028T090634Z/fixture_patches.json), [finestre GNU](../Risultati/GUI_S33/window_transition_cpu_20261028T090634Z/gnu_windows.txt), [risultato e hash](../Risultati/GUI_S33/window_transition_cpu_20261028T090634Z/verified_evidence.json). Nessun firmware, GNU, fotocamera o SD modificato; **NON_INSTALLARE**.

## Estensione: precedente presente

Una seconda prova del 28 ottobre aggiunge due casi con **B già corrente** e A richiesto; il callback sintetico di A risponde `−1` all'evento `0x4403`. Se il bit 9 di B è zero, il gestore prova B, invia a B gli eventi `0x4403`, `0x4401` con argomento zero e `0x4405`, e termina con B corrente e ritorno 1. Se il bit 9 di B è uno, termina con ritorno 0 dopo il solo `0x4403` ad A, lasciando B corrente. Le risposte successive di B sono `−2`, ID volutamente non risolvibile nella tabella sintetica.

Tutti i **sei casi** dell'estensione passano, inclusi i quattro precedenti. Le risposte dei callback, i flag e i descrittori sono ancora sintetici: questo osserva un comportamento condizionale del gestore, non un ritorno dalla schermata ISO o tempo reale. [Casi](../Risultati/GUI_S33/window_transition_cpu_20261028T090741Z/cases.json), [trace](../Risultati/GUI_S33/window_transition_cpu_20261028T090741Z/cases.trace), [risultato e hash](../Risultati/GUI_S33/window_transition_cpu_20261028T090741Z/verified_evidence.json).
