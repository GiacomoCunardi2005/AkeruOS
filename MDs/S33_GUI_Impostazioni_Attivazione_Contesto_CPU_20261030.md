# Impostazioni — attivazione del contesto dopo l'apertura

La modalità `--arm` del [banco GNU ARC700](../Python_Trace_Scripts/s33_probe_gui_settings_back_request_cpu.py) verifica una possibile regola per il quarto tasto: il banco pone il flag sintetico di ritorno a 1 solo dopo una richiesta del modello e se la chiamata originale al manager restituisce 1 **e** il descrittore corrente è `GeneralSetupMenu` `0x99242C`.

| Caso | Apertura impostazioni | Flag dopo apertura | Seguito |
|---|---|---:|---|
| Guardia inattiva | Ritorno 1, descrittore `0x99242C` | 1 | Il banco inietta indietro; il trampoline sperimentale riapre il descrittore sintetico AkeruOS e cancella il flag. |
| Guardia forzata | Ritorno 0, resta corrente il descrittore sintetico AkeruOS | 0 | Il banco non invia l'evento di ritorno dalle impostazioni non aperte. |

Due casi **PASS**, stack conservato: [casi](../Risultati/GUI_S33/descriptor_settings_arm_cpu_20261030T155419Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/descriptor_settings_arm_cpu_20261030T155419Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/descriptor_settings_arm_cpu_20261030T155419Z/fixture_patches.json). Passano anche le varianti preesistenti: redirect 3 casi, fallback con guardia aperta 4, fallback con guardia attiva 4 e registratore 2, tutte nelle directory con suffisso `20261030T155419Z`. Il tentativo `155356Z` è FAIL in assemblaggio per un'etichetta duplicata; nessun caso CPU vi è stato eseguito.

La regola e il flag sono **nel banco**, non nel firmware: non esiste ancora un produttore integrato né una posizione di memoria garantita. Questa prova esercita un rifiuto dovuto alla guardia, non ogni errore o possibile deviazione durante l'apertura. Il manager, il modello e le fixture operano su contesti sintetici; non sono dimostrati visualizzazione, lifecycle reale, concorrenza, tasti fisici o persistenza. L'evento di ritorno è imposto dal banco. Nessun firmware originale, fotocamera o SD modificati; **NON_INSTALLARE**.
