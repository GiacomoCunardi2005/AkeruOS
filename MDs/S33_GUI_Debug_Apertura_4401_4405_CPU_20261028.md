# S33 V1.1 — apertura diagnostica con 0x4401 e 0x4405 originali

Il 28 ottobre 2026 ho esteso la [prova precedente](S33_GUI_Debug_Inizializzazione_Manager_CPU_20261028.md) eliminando la fixture del gestore `0x4401`. In GNU ARC700 vengono eseguiti il WindowManager `0x145180`, i gestori originali `0x16A05C` e `0x16A188` per gli eventi `0x4401` e `0x4405`, i dispatcher e i callback diagnostici ISO e tempo. I descrittori iniziali e le istruzioni considerate sono confrontati con `DUMPS/MainCode.dmp`; le modifiche ai descrittori avvengono nella copia di laboratorio.

Nei **due casi PASS**, con nessuna schermata precedente, argomento di ingresso sintetico 123 e indice ISO sintetico 6:

- Il gestore di `0x4401` richiede due chiamate a `0x1455E4`, sostituita da una fixture registratrice, con i riferimenti originali `0x16A93C` e `0x16A944` e rispettivamente il descrittore e il valore `0x4401`.
- Al termine, la word dei flag del descrittore è `0x702` per tempo e `0x742` per ISO; la word a `+24` è 123. Il gestore mantiene il rispettivo descrittore come corrente e ritorna 1.
- Il callback tempo richiede il testo iniziale `AUTO`; quello ISO cerca il valore 6 nella lista originale e richiede la posizione 7. Testo e selezione sono intercettati da fixture.

L'ottenimento dei controlli, le due chiamate a `0x1455E4`, la selezione della lista, la scrittura del testo e il disegno restano simulati. Le chiamate registrate non dimostrano che le risorse siano realmente registrate, visualizzate o utilizzabili. Il test non osserva pulsanti fisici, dati runtime, ritorno al nuovo sottomenu, persistenza o scatto. Nessuna modifica a firmware, GNU, fotocamera o SD; **NON_INSTALLARE**.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_window_start_cpu.py), [due casi](../Risultati/GUI_S33/debug_window_start_cpu_20261028T091451Z/cases.json), [fixture](../Risultati/GUI_S33/debug_window_start_cpu_20261028T091451Z/fixture_patches.json), [traccia](../Risultati/GUI_S33/debug_window_start_cpu_20261028T091451Z/cases.trace), [risultato e hash](../Risultati/GUI_S33/debug_window_start_cpu_20261028T091451Z/verified_evidence.json).
