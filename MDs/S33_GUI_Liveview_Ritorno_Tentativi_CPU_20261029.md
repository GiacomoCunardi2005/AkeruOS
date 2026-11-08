# Tentativi di ritorno alla live view

Il 29 ottobre 2026 ho esteso il [banco con descrittore live view precedente](S33_GUI_Liveview_Descrittore_Precedente_CPU_20261029.md): dopo l'apertura del menu sintetico e il passaggio del modello a esposizione, il banco chiama esplicitamente il manager originale `0x1453E4(1,0)` per richiedere `CaptureLiveview`. Questa richiesta è del banco, non è ancora collegata a un tasto o a un'azione del modello.

La transizione raggiunge il callback originale `0x6524F4` e il ramo di inizializzazione `0x65275A` con evento `0x4401`, ma **nessuno dei tentativi completa il ritorno**:

| Tentativo | Ulteriore stato predisposto | Arresto nel simulatore |
|---|---|---|
| [223642Z](../Risultati/GUI_S33/liveview_return_attempt_cpu_20261029T223642Z/verified_evidence.json) | Nessuno | Lettura halfword non mappata `0x0FEF0004` a `0x263DE8`, dopo `0x18AAB4→0x263DDC`. |
| [223650Z](../Risultati/GUI_S33/liveview_return_mmio_probe_cpu_20261029T223650Z/verified_evidence.json) | MMIO `0x0FEF0000` sintetico, lettura a +4 inizialmente zero | Scrittura non mappata `0x47D124` a `0x13A96C`; il codice aveva richiesto di inizializzare il contesto restituito da `0x660C2C`. |
| [223656Z](../Risultati/GUI_S33/liveview_return_context_probe_cpu_20261029T223656Z/verified_evidence.json) | Aggiunta RAM sintetica che include `0x47D124` | Lettura non mappata `0x00C8EABD` a `0x0CC2DE`. |
| [223705Z](../Risultati/GUI_S33/liveview_return_data_probe_cpu_20261029T223705Z/verified_evidence.json) | Aggiunto il blocco originale 8 al suo indirizzo candidato; byte letto confrontato col dump | Lettura non mappata `0x43C53E` a `0x0DF44E`, dopo 330.634 istruzioni simulate. |

I log e le tracce sono nelle rispettive cartelle; i banchi sono in `Python_Trace_Scripts/s33_verify_gui_liveview_return*_cpu.py`. Il quarto banco conferma che `0x00C8EABD` cade nel blocco 8 estratto dal dump, ma non prova caricamento o mappa runtime sulla fotocamera. L'accesso successivo riguarda un contesto ancora da caratterizzare: aggiungere RAM zero non dimostrerebbe un'inizializzazione corretta.

Gli assert di ritorno e descrittore finale non sono raggiunti. Nessun risultato dimostra una schermata visibile, l'effettiva chiusura o riapertura della live view, tasti fisici, AE o scatto. Modalità, gate, RAM e MMIO sono sintetici, alcuni servizi sono fixture e il DSP è sperimentale; nessun firmware o hardware modificato. **NON_INSTALLARE**.
