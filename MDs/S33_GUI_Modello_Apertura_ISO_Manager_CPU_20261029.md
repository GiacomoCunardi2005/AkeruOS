# Modello GUI: apertura ISO con il manager originale

Il 29 ottobre 2026 ho esteso la [prova del modello e della conferma](S33_GUI_Modello_Richiesta_ISO_Conferma_CPU_20261029.md). Il [nuovo banco](../Python_Trace_Scripts/s33_verify_gui_model_open_iso_transition_cpu.py) usa il generatore logico e la coda originali per produrre `0x700` dal tasto logico 14. Il banco estrae l'evento e lo consegna al modello C, predisposto nella schermata esposizione; quando riceve `AKERU_OPEN_ISO`, chiama il servizio originale `0x1453E4` con ID `0x3F`. Il manager apre il descrittore diagnostico ISO `0x989FCC`.

Il banco imposta poi la selezione nel controllo sintetico e consegna esplicitamente l'evento `0x4801` al dispatcher originale. Risultati:

| Selezione | Byte diagnostico / indice / valore software | Descrittore finale |
|---|---|---|
| ISO 125 | 6 / 6 / 125 | `0x987AF8`, menu diagnostico |
| Exit | 88 / 77 / 555, sentinelle invariate | `0x987AF8` |
| Auto | 0 / 0 / 0 | `0x987AF8` |

[Tre casi PASS](../Risultati/GUI_S33/model_open_iso_transition_cpu_20261028T234607Z/verified_evidence.json), 43.054 istruzioni complessive: controllati richiesta del modello, record degli eventi `0x700` e `0x701`, apertura ISO, campi risultanti, descrittore di ritorno e stack. [Risultati](../Risultati/GUI_S33/model_open_iso_transition_cpu_20261028T234607Z/cases.json), [fixture](../Risultati/GUI_S33/model_open_iso_transition_cpu_20261028T234607Z/fixture_patches.json) e [traccia](../Risultati/GUI_S33/model_open_iso_transition_cpu_20261028T234607Z/cases.trace). La routine originale di conferma non è modificata: il ritorno al menu diagnostico resta un problema concreto da risolvere per il sottomenu esposizione desiderato.

La schermata iniziale e lo stato del manager sono predisposti dal banco; il modello C è chiamato direttamente, non attraverso un nuovo descrittore di finestra registrato. La traduzione dell'azione in apertura è anch'essa nel banco, non nell'integrazione firmware. Recupero controllo, testo, selezione, filtri e altri servizi sono fixture, come le selezioni e la consegna dell'evento di conferma; il DSP è sperimentale. Nessun rendering, tasto fisico, guadagno sensore, AE, scatto o persistenza dimostrati. Firmware e fotocamera non modificati; **NON_INSTALLARE**.
