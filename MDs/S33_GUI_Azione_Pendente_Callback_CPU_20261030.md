# S33 — azione pendente e risposta del manager

Il modello C di laboratorio `AkeruOS/ui/menu.c` offre `akeru_menu_defer_event` e `akeru_menu_take_action`: una richiesta resta nello slot finché non viene prelevata. Il rilascio del tasto o un evento non relativo non cancellano la richiesta; una seconda azione restituisce `-2` senza cambiare schermata o richiesta già pendente. Il contratto richiede un chiamante sequenziale che conservi e ripresenti l'evento dopo aver prelevato la prima azione: non c'è una coda interna né sincronizzazione concorrente.

## Prove

`make -C AkeruOS menu-model-verify` verifica il modello su host con UBSan e GNU ARC700, inclusi rilascio, evento estraneo, slot occupato, ripresentazione e input non validi: [risultati](../Risultati/GUI_S33/akeru_menu_model_20261030T152944Z/). Anche `make -C AkeruOS color-pipeline-verify` passa su host e ARC700: [risultati](../Risultati/GUI_S33/akeru_color_pipeline_20261030T152944Z/).

Nel [banco CPU](../Python_Trace_Scripts/s33_verify_gui_manager_deferred_action_cpu.py), tasti logici sintetici producono eventi attraverso il codice di accodamento originale; il banco li estrae e li consegna esplicitamente al dispatcher originale `0x169E1C`/`0x169D78`. Il descrittore corrente è predisposto in RAM sintetica e, nella sola copia di laboratorio, il callback è sostituito con un ponte al modello C. Nei 12 casi schermata/tasto la richiesta generata dalla pressione è ancora presente dopo il rilascio e viene prelevata dal banco; l'evento senza azione lascia lo slot vuoto. [Risultati, manifest e traccia](../Risultati/GUI_S33/manager_deferred_menu_cpu_20261030T153004Z/).

Un caso aggiuntivo parte con schermata esposizione e richiesta ISO già pendente. L'evento diaframma `0x2180` è generato ed estratto dalla coda; il callback restituisce **-2**, ma il dispatcher originale restituisce **1**. La schermata e la richiesta ISO restano invariate. Il banco preleva ISO e ripresenta esplicitamente lo stesso record al dispatcher: il callback restituisce 1 e la richiesta diaframma viene inserita. I ritorni sono registrati separatamente in [busy.json](../Risultati/GUI_S33/manager_deferred_menu_cpu_20261030T153004Z/busy.json).

## Conseguenza e limiti

Il ritorno del dispatcher non permette al suo chiamante di distinguere questo `-2` dal successo. In questo banco solo la ripresentazione imposta dal programma di prova recupera la seconda azione; **non è dimostrato alcun recupero automatico** nella fotocamera. Un'integrazione deve preservare o accodare l'evento prima che venga perso e affrontare la concorrenza; la sola aggiunta dello slot pendente non basta.

Il ciclo permanente del WindowManager, scheduler, tasti fisici, rendering, esecuzione asincrona dell'azione e integrazione firmware non sono provati. Il modello DSP, lo stato e vari servizi sono sintetici; i test non confermano il comportamento sulla macchina. La chiamata diretta al pannello iride resta bloccante nella prova senza uscita descritta in [rapporto precedente](S33_GUI_Callback_Iride_Sincrono_CPU_20261030.md). Nessuna installazione: **NON_INSTALLARE**.
