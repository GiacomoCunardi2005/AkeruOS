# GUI — dispatcher Nikon, coda e richiesta iride

Il 30 ottobre 2026 il [banco coda → modello → iride](S33_GUI_Coda_Iride_Registri_CPU_20261030.md) è stato esteso con il dispatcher originale Nikon. Nei quattro casi iride, un tasto logico 67 sintetico produce nella coda l'evento `0x2180`. Il banco lo estrae e lo consegna al dispatcher originale `0x169E1C → 0x169D78`, con un descrittore CaptureMenu predisposto corrente e senza controllo attivo. Nella **sola copia laboratorio**, il callback del descrittore a `0x7CAFE8` è sostituito da un ponte al modello C ARC700. Il modello, predisposto sul sottomenu esposizione, emette la richiesta diaframma; il banco chiama quindi il dispatcher diagnostico e la catena originale del pannello iride.

| Tasto pannello sintetico | Condizione imposta | Stato iniziale → finale | Registri sintetici dopo la richiesta |
|---|---|---|---|
| 9, Big | libera | 9 → 1 | `0x0FEF0388=A5A4`, `0x0FF04024=A5B0` |
| 10, Small | libera | 1 → 9 | `0x0FEF0388=A5A4`, `0x0FF04024=A5A8` |
| 9, Big | occupata | 9 → 9 | `A5A7`, `A5B8` invariati |
| 10, Small | occupata | 1 → 1 | `A5A7`, `A5B8` invariati |

Un quinto caso usa tasto logico 14, evento `0x700`: il manager arriva al modello, che richiede ISO; il banco non avvia il pannello iride e i registri restano invariati. In tutti i casi si verificano record e ritorno della coda, azione, ingressi al manager e callback, stato, registri e stack. La traccia verifica cinque passaggi nel dispatcher/ponte, quattro nel pannello e richiesta originale `0x235B0C`, uno ciascuno nei rami Big e Small.

Nel tentativo `152517Z` il verificatore leggeva il file sbagliato dopo aver scritto le copie dei blocchi. Nel tentativo `152524Z` una fixture del precedente banco sostituiva anche `0x1453F4`, usata dal manager per individuare il descrittore corrente, e il modello non era raggiunto. Il banco finale conserva **originale** `0x1453F4` e verifica i byte delle finestre manager e richiesta contro il dump. Nessun originale è stato modificato.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_manager_queue_iris_request_cpu.py), [manifest e traccia](../Risultati/GUI_S33/manager_queue_iris_request_mmio_cpu_20261030T152542Z/verified_evidence.json), [casi](../Risultati/GUI_S33/manager_queue_iris_request_mmio_cpu_20261030T152542Z/cases.json).

Il banco continua a estrarre e consegnare l'evento al manager, predispone il descrittore e chiama il dispatcher iride dopo l'azione; non dimostra scheduler, apertura/chiusura reale della finestra o integrazione nel firmware. Tasti, handle, occupazione e servizi sono fixture; registri MMIO sono memoria inerte, DSP sperimentale. Nessuna prova di tasti fisici, movimento ottico, AE, f/ effettivo o scatto; **NON_INSTALLARE**.
