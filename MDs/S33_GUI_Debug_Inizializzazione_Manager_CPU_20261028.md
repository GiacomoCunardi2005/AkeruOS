# S33 V1.1 — inizializzazione diagnostica attraverso il gestore

Il 28 ottobre 2026 ho esteso la [prova d'ingresso del WindowManager](S33_GUI_Debug_Ingresso_Manager_CPU_20261028.md): in GNU ARC700 il gestore originale `0x145180` invia anche `0x4405` al gestore originale `0x16A188`, che raggiunge i wrapper e i callback originali delle schermate diagnostiche ISO e tempo. Descrittori, tabelle, record ISO e testo iniziale sono confrontati con `DUMPS/MainCode.dmp` V1.1.

Nei **due casi PASS**, partendo senza schermata precedente e con controllo sintetico:

| Schermata | Risultato osservato nel callback originale |
| --- | --- |
| ISO | Con indice software iniziale 6 e una lista sintetica che punta ai 24 record originali, la ricerca originale trova la posizione 7 e la passa alla fixture di selezione. |
| Tempo | Il callback passa alla fixture di testo il puntatore alla stringa iniziale originale `AUTO`. |

In entrambi i casi il gestore termina con ritorno 1 e il rispettivo descrittore corrente. L'evento `0x4401`, l'ottenimento dei controlli, la selezione ISO, la scrittura del testo e il disegno restano **fixture**; `0x4405` e il callback diagnostico sono invece originali. Il banco non dimostra che la voce sia selezionata o che il testo compaia effettivamente sul display. Il valore 6 e il contesto della lista sono dati di laboratorio, non stato osservato sulla fotocamera.

Non sono provati caricamento reale dei controlli, ordine delle attività, tasti fisici, ritorno al sottomenu richiesto, effetto sul sensore o persistenza. La richiesta di uscita delle schermate diagnostiche verso `DEBUG MODE MENU` rimane invariata. Nessun firmware, GNU, fotocamera o SD modificato; **NON_INSTALLARE**.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_window_initialize_cpu.py), [due casi](../Risultati/GUI_S33/debug_window_initialize_cpu_20261028T091311Z/cases.json), [fixture](../Risultati/GUI_S33/debug_window_initialize_cpu_20261028T091311Z/fixture_patches.json), [traccia](../Risultati/GUI_S33/debug_window_initialize_cpu_20261028T091311Z/cases.trace), [risultato e hash](../Risultati/GUI_S33/debug_window_initialize_cpu_20261028T091311Z/verified_evidence.json).
