# Coda menu dopo il manager AutoScene — 5 novembre 2026

Il banco di [rollback dell'inizializzazione anticipata](S33_GUI_Autoscene_Inizializzazione_Rollback_CPU_20261105.md) ora dispone della variante `--post-manager`. Nella sola copia laboratorio, un osservatore sostituisce il sito `0x65C6AC` e la successiva diramazione: richiama `0x1453E4`, controlla il risultato e il descrittore corrente, e prosegue verso la destinazione originale `0x65B1B8`. Solo quando il manager restituisce 1 **e** il descrittore è quello sintetico `0x2050000`, l'osservatore chiama `akeru_menu_complete(...,1)` e imposta `AKERU_MAIN`. Il callback sperimentale registra `0x4401` e il suo argomento, ma in questa variante non modifica la coda.

Per ciascuno degli eventi logici `0x700` e `0x2180` sono verificati questi casi:

| Condizione | Ritorno manager | Descrittore finale | Coda |
|---|---:|---|---|
| Guardia attiva | 0 | live view | esposizione, sospesa |
| Guardia rimossa, `0x4405` restituisce −1 | 1 | live view ripristinata | esposizione, sospesa |
| Guardia rimossa, nessun errore iniettato | 1 | menu sintetico | completata; il successivo `0x700` apre colore nel modello |

**4/4 prove PASS**: eventi `0x700` e `0x2180`, ciascuno con e senza errore `0x4405` iniettato. Ogni prova include il tentativo preliminare con guardia attiva. Durante `0x4401` è verificato che la coda sia ancora sospesa nella schermata esposizione; gli argomenti registrati sono rispettivamente 4 e 5. Con errore, ritorno 1 non induce il completamento perché il descrittore è di nuovo live view. Il dispatcher restituisce 1 anche in questo caso.

Evidenze: [0x700 riuscito](../Risultati/GUI_S33/autoscene_post_manager_cpu_20261105T103951586553Z/verified_evidence.json), [0x700 con rollback](../Risultati/GUI_S33/autoscene_post_manager_cpu_20261105T103953318673Z/verified_evidence.json), [0x2180 riuscito](../Risultati/GUI_S33/autoscene_post_manager_cpu_20261105T103955191733Z/verified_evidence.json), [0x2180 con rollback](../Risultati/GUI_S33/autoscene_post_manager_cpu_20261105T103956983672Z/verified_evidence.json). Restano riproducibili sia il [difetto dell'inizializzazione anticipata](../Risultati/GUI_S33/autoscene_lifecycle_failure_cpu_20261105T103958835318Z/verified_evidence.json), sia il [percorso anticipato senza errore](../Risultati/GUI_S33/autoscene_lifecycle_entry_cpu_20261105T104000690158Z/verified_evidence.json).

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_autoscene_key_reenter_cpu.py --lifecycle-entry --post-manager`; aggiungere `--fail-entry` e/o `--event-2180` per gli altri casi. Ogni cartella contiene trace, copie del verificatore e patch fixture. Le altre sequenze ereditate vengono eseguite ma **non validate** da questa variante.

Il risultato è limitato a questo specifico sito, alle condizioni sequenziali e allo stato sintetico provati: il flag di abilitazione, il descrittore, il callback, le guardie, i servizi e la consegna degli eventi sono fixture; dopo la sottoprova il banco ripristina stato artificialmente. Il caso di partenza ha coda sospesa senza eventi pendenti. Non sono provati altri ingressi al menu, errori differenti, concorrenza, tempo di vita e indirizzo della RAM, registrazione runtime, rendering o tasti fisici. L'osservatore e il redirect globale ID 2 non sono una patch pronta per la fotocamera. Nessun firmware originale o supporto modificato; **NON_INSTALLARE**.
