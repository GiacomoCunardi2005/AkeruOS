# S33 V1.1 — interpretazione del redirect in CPU emulata

28 ottobre 2026. Nove casi eseguono la routine originale `0x14510C` e i suoi helper `0x14503C` e `0x14507C` su GNU ARC700; descrittori, tabella, argomenti del chiamante e RAM sono sintetici. Le istruzioni e i letterali del perimetro sono confrontati con `DUMPS/MainCode.dmp`. La routine è chiamata direttamente: non sono eseguiti il WindowManager `0x145180` o callback di schermate.

| Risposta in ingresso | Condizione sintetica | Risultato osservato |
| --- | --- | --- |
| `0xFFFFFFFF` | precedente nullo | stato 0, destinazione nulla; argomento d'uscita invariato |
| `0xFFFFFFFF` | precedente presente, bit 9 a 0 | stato 0, destinazione precedente, argomento 0 |
| `0xFFFFFFFF` | precedente presente, bit 9 a 1 | stato 0, destinazione nulla; argomento d'uscita invariato |
| `0x12340001` / `0xFFFE0001` | ID 1 risolto nella tabella sintetica | stato 0, destinazione trovata, argomento rispettivamente 4660 / −2 |
| ID negativo, fuori intervallo, voce nulla o tabella assente | quattro casi, argomento alto positivo | stato 1, destinazione nulla, argomento alto comunque scritto |

Il caso `−1` è speciale e non equivale semplicemente a un ID negativo. La metà bassa degli altri valori è trattata come ID signed a 16 bit; la metà alta come argomento signed a 16 bit. Per `−1` con fallback non disponibile il campo argomento non viene azzerato dalla routine. La destinazione nulla resta il dato decisivo nel percorso verificato staticamente; non si deve assumere che il campo argomento sia sempre inizializzato.

Questa prova precisa la semantica del componente usabile da un eventuale ritorno, ma non dimostra che la schermata ISO/tempo o un nuovo menu producano tali risposte, né che un redirect venga seguito durante una transizione effettiva. Per le condizioni del chiamante vedere [analisi statica del ciclo](S33_GUI_WindowManager_Ciclo_e_Redirect_20261028.md); le schermate diagnostiche richiedono esplicitamente il menu debug in uscita.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_window_redirect_cpu.py`. [Risultati e hash](../Risultati/GUI_S33/window_redirect_cpu_20261028T090318Z/verified_evidence.json), [casi](../Risultati/GUI_S33/window_redirect_cpu_20261028T090318Z/cases.json), [disassemblaggio](../Risultati/GUI_S33/window_redirect_cpu_20261028T090318Z/gnu_windows.txt). Nessuna prova di registrazione runtime, grafica, tasti, concorrenza o hardware. Nessuna modifica a firmware, GNU, fotocamera o SD. **NON_INSTALLARE**.
