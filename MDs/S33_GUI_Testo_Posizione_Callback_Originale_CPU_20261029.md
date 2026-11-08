# GUI — posizione del testo nel callback originale

Il 29 ottobre 2026 ho esteso la [catena testo](S33_GUI_Catena_Testo_Originale_CPU_20261029.md): oltre alle routine originali della voce e della preparazione testo, il banco esegue anche il callback originale `0x1870DC`. Questo passa a `0x156768` posizione e puntatore della stringa; `0x156768` è sostituito con una fixture registratrice, quindi non vengono prodotti caratteri o pixel.

Con controllo, posizione iniziale, metriche e contesto sintetici, i **16 casi PASS** coprono sette etichette non nulle e un campo zero nei blocchi italiano e inglese. Ogni etichetta non nulla raggiunge una volta la fixture finale con puntatore previsto e coordinate **(12, 70)**; il campo zero non la raggiunge. Le coordinate sono risultato del caso di laboratorio, non misure del display Nikon. I blocchi testo e il buffer delle etichette restano invariati e lo stack viene conservato.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_item_text_position_cpu.py), [casi](../Risultati/GUI_S33/menu_text_position_cpu_20261029T225743Z/cases.json), [manifest e tracce](../Risultati/GUI_S33/menu_text_position_cpu_20261029T225743Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/menu_text_position_cpu_20261029T225743Z/fixture_patches.json). La precedente esecuzione `225730Z` ha passato il controllo dei puntatori; quella finale aggiunge la registrazione e il controllo delle coordinate.

La prova usa il solo ramo e la posizione configurati nel banco; font, allineamento in altri rami, clipping, backend di `0x156768`, RAM fisica, tasti e display non sono verificati. Nessuna modifica a firmware o dispositivo; **NON_INSTALLARE**.
