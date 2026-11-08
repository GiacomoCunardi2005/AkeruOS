# Selettore classi GUI: prova CPU delimitata — 28 ottobre 2026

Il verificatore [s33_verify_gui_debug_class_table_cpu.py](../Python_Trace_Scripts/s33_verify_gui_debug_class_table_cpu.py) esegue il lookup originale V1.1 `0x145020` nel percorso delle schermate diagnostiche TIME e ISO. Il WindowManager riceve una **tabella classi sintetica**, con handler di registrazione distinti per classe. Le risorse originali conducono rispettivamente alle classi `[7, 2, 2, 2, 1, 1]` e `[7, 9]`, ciascuna con evento `0x4401`; entrambe le prove passano e preservano lo stack.

Evidenze: [risultati e fixture](../Risultati/GUI_S33/debug_class_table_cpu_20261028T092017Z/), inclusi `cases.json`, `fixture_patches.json`, trace e snapshot del verificatore. I byte originali del lookup sono confrontati con `DUMPS/MainCode.dmp`; le patch di servizio sono elencate separatamente.

La tabella classi e gli handler non sono originali; recupero dei controlli, selezione, testo e disegno usano fixture. Non sono dimostrati costruzione dei controlli reali, tasti fisici, rendering, modifica dei parametri o comportamento della fotocamera. CPU emulata, non hardware; **NON_INSTALLARE**.
