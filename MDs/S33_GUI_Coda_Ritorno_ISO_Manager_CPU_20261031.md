# S33 V1.1 — coda AkeruOS e ritorno ISO nel manager simulato

**Data:** 2026-10-31. Sei sequenze GNU ARC700 PASS usando il manager e il callback ISO originali con servizi e stato sintetici. Il banco deriva da `s33_verify_gui_model_iso_return_dispatch_cpu.py` e vi collega la coda sperimentale AkeruOS.

Per ogni sequenza il banco inserisce l'evento ISO nella coda del modello, estrae l'azione di apertura e chiede esplicitamente al manager originale di aprire il descrittore ISO `0x989FCC`. Una successiva pressione `0x580` viene offerta direttamente alla coda sospesa: restituisce 0 e non è conservata. **Il banco non consegna tale pressione al dispatcher ISO**, quindi non dimostra cosa accadrebbe sulla schermata fisica.

Il callback ISO originale riceve poi una conferma iniettata. Un trampoline di laboratorio usa il contesto sintetico per richiedere il ritorno al descrittore sperimentale `0x2050000`; solo se il manager restituisce 1 **e** quel descrittore è corrente, consuma il contesto e chiama `akeru_menu_complete`. La prova osserva:

| Caso | Prima destinazione dopo conferma | Coda dopo prima conferma |
|---|---|---|
| ISO 125 o Exit, contesto speciale 1 | descrittore sperimentale | riattivata, coda vuota |
| ISO 125, guardia manager forzata | ISO ancora corrente | ancora sospesa, contesto conservato |
| contesto 0 o 2 | menu diagnostico | ancora sospesa, nessun ritorno al modello |

Nel caso di guardia il banco rimuove la guardia e impone una seconda conferma: allora ottiene il descrittore sperimentale e riattiva la coda. Nei casi speciali, dopo il ritorno, il banco azzera artificialmente il controllo attivo e consegna al dispatcher l'evento `0x2180`: il callback sperimentale accoda ed estrae `AKERU_OPEN_APERTURE`. La prova non apre la schermata iride. La traccia e gli assert controllano inoltre i valori diagnostici ISO/Exit, le chiamate, i descrittori e la pila.

Il contesto di ritorno, il descrittore senza risorse e il trampoline sono **solo nel banco**; il callback ISO è modificato nella sola copia di laboratorio. Le fixture di lifecycle, selezione, filtro, lock e rendering sono elencate nell'evidenza. L'armamento del contesto, la consegna degli eventi, la guardia e la seconda conferma sono imposti dal banco. Non è dimostrato come integrare il segnale di completamento nel firmware, come instradare gli eventi durante la transizione, cosa fare su tutte le cause d'errore, né concorrenza, mapping fisico, resa ISO o scatto. I casi ordinari non riattivano la coda poiché non tornano al descrittore sperimentale: serve un lifecycle reale per gestire altre destinazioni.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_model_iso_return_queue_cpu.py`; [risultati](../Risultati/GUI_S33/model_iso_return_queue_cpu_20261031T210405Z/cases.json), trace, snapshot e fixture nella stessa directory. Regressioni: ritorno senza coda 6 PASS `model_iso_return_dispatch_cpu_20261031T210411Z/`, modello menu host/GNU PASS `akeru_menu_model_20261031T210411Z/`. Primo tentativo `...210352Z` FAIL in link del trampoline per simbolo C non collegato; successivo banco usa un ponte di laboratorio risolto al link. Il dump originale è verificato per le finestre usate e la fotocamera non è stata toccata. **NON_INSTALLARE.**
