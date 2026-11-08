# GUI — coda tasti e richiesta iride nella stessa prova

Il 30 ottobre 2026 ho esteso il [banco modello → richiesta iride](S33_GUI_Iride_Richiesta_Registri_CPU_20261030.md) con il produttore e la coda originali Nikon. Nei quattro casi iride il banco inietta il tasto **logico** 67 nello stato sintetico, chiama `0x16F72C` e poi estrae dalla coda originale con `0x17BD4C` il record contenente evento `0x2180`. Passa esplicitamente quell'evento al modello C già predisposto sulla schermata esposizione; quando il modello chiede il diaframma, chiama il dispatcher diagnostico `0x2C4FAC(0x50)`. Da lì vengono eseguiti pannello, setter, richiesta `0x235B0C` e, per i casi non occupati, percorsi Big/Small originali.

| Tasto diagnostico simulato | Occupazione imposta | Stato iniziale → finale | `0x0FEF0388` sintetico | `0x0FF04024` sintetico |
|---|---|---|---|---|
| 9, Big | libera | 9 → 1 | `A5A7 → A5A4` | `A5B8 → A5B0` |
| 10, Small | libera | 1 → 9 | `A5A7 → A5A4` | `A5B8 → A5A8` |
| 9, Big | occupata | 9 → 9 | `A5A7 → A5A7` | `A5B8 → A5B8` |
| 10, Small | occupata | 1 → 1 | `A5A7 → A5A7` | `A5B8 → A5B8` |

In un quinto caso il tasto logico 14 produce l'evento `0x700` e il modello richiede ISO: il banco non chiama il dispatcher iride e i registri sintetici non cambiano. Il verificatore controlla l'evento estratto e il successo dell'estrazione, l'azione del modello, i quattro ingressi al dispatcher e alla richiesta, un ingresso per ciascun percorso Big/Small, lo stato, i registri e lo stack. I due tasti diagnostici 9/10 sono simulati separatamente dal tasto logico che apre il pannello.

Il primo tentativo `103044Z` si fermava per una regione RAM non mappata; il secondo `103052Z` estraeva l'evento corretto ma il banco non salvava il ritorno di `0x17BD4C` nel campo confrontato. Il banco finale salva esplicitamente il ritorno e verifica il record; non si tratta di una correzione al firmware.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_queue_model_iris_request_cpu.py), [casi](../Risultati/GUI_S33/queue_model_iris_request_mmio_cpu_20261030T152441Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/queue_model_iris_request_mmio_cpu_20261030T152441Z/verified_evidence.json).

La consegna dell'evento estratto al modello e la chiamata del dispatcher sono eseguite dal banco, non dal WindowManager. Lock, filtro, handle, occupazione, servizi di attuazione e tasti del pannello sono fixture; MMIO è memoria inerte e il modello DSP è sperimentale. Non sono provati corrispondenza con tasti fisici, movimento ottico, AE, numero f/ o scatto. Firmware e fotocamera invariati; **NON_INSTALLARE**.
