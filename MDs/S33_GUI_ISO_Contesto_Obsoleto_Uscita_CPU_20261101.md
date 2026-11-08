# S33 V1.1 — contesto ISO rimasto armato dopo uscita alternativa

**Data:** 2026-11-01. Otto sequenze GNU ARC700 con manager e callback ISO originali, stato e lifecycle sintetici. È una prova del raccordo sperimentale AkeruOS, non un comportamento attribuito al firmware Nikon senza modifica.

Nel [banco precedente](S33_GUI_ISO_Uscita_Liveview_Manager_CPU_20261101.md) il contesto di ritorno era ancora disarmato durante l'uscita ISO. Qui il banco imposta il flag sperimentale a 1 prima di consegnare `0x2180`; sotto le condizioni sintetiche già note il manager originale rende corrente la live view `0x783AE8`, il cui callback è una fixture. Il flag resta 1. Il banco richiede poi una nuova apertura ISO tramite il manager originale `0x1453E4(0x3F,0)`, senza armare un nuovo contesto, e inietta una conferma ISO 125.

| Variante | Flag dopo uscita / prima di riapertura | Destinazione alla conferma successiva |
| --- | --- | --- |
| Nessuna cancellazione | 1 / 1 | descrittore AkeruOS sintetico `0x2050000`; vecchio contesto consumato |
| Cancellazione imposta dal banco dopo l'uscita | 1 / 0 | menu diagnostico originale `0x987AF8` |

Entrambe le varianti impostano i campi software ISO a 6 / 6 / 125 nelle condizioni del banco. La prima dimostra una deviazione **causata dal trampoline sperimentale e dal suo vecchio flag sintetico**: non prova che il software Nikon originale abbia un flag analogo. La seconda dimostra solo che cancellare quel flag nel momento imposto evita la deviazione in questa sequenza. Non implementa una cancellazione automatica e non identifica un segnale reale, un'area RAM sicura, atomicità, ownership o gestione della coda in tutti i casi. La coda rimane sospesa nella variante cancellata perché non è stato definito un lifecycle reale di riattivazione.

Il banco verifica descrittori dopo pressione/rilascio, flag prima e dopo uscita e cancellazione, riapertura ISO, valori, esiti del ritorno, coda e stack. Rilascio, riapertura e conferma sono esplicitamente imposti; controllo attivo nullo, descrittore AkeruOS, trampoline, risorse e servizi sono fixture. Le altre sei sequenze verificano le condizioni preesistenti. Non si dimostrano associazione ai pulsanti fisici, scheduler, GUI visibile, qualità ISO o comportamento allo scatto.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_iso_escape_context_cpu.py`; [otto casi PASS](../Risultati/GUI_S33/iso_escape_context_cpu_20261101T093921Z/cases.json), trace, fixture, snapshot e hash nella stessa directory. Regressioni PASS: sei sequenze di uscita `iso_escape_liveview_cpu_20261101T093932Z/` e modello menu host/GNU `akeru_menu_model_20261101T093932Z/`. I due tentativi `...093906Z` e `...093910Z` sono conservati FAIL: rispettivamente un conteggio di selezioni e i conteggi degli ingressi al manager non erano stati aggiornati per le nuove riaperture; nessun firmware o GNU è stato modificato. **NON_INSTALLARE.**
