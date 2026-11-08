# Impostazioni — ritorno contestuale al menu sintetico

Il 30 ottobre 2026 ho esteso il [banco del ritorno impostazioni](../Python_Trace_Scripts/s33_probe_gui_settings_back_request_cpu.py) con l'opzione `--redirect`. Come nella prova precedente, il modello riceve l'evento logico `0x2700`, il banco apre `GeneralSetupMenu` col manager originale e inietta `0x580`. Nella sola copia di laboratorio, la chiamata di apertura dell'handler originale viene deviata a un trampoline: con flag sintetico 1 esso chiama il manager originale `0x145180` per riaprire il descrittore sintetico del menu `0x2050000`. Azzera il flag soltanto se il manager ritorna 1, il descrittore corrente coincide con quello atteso e il flag è ancora 1.

| Caso | Prima richiesta di ritorno | Stato osservato |
|---|---|---|
| Flag 1 | Transizione accettata | Descrittore sintetico corrente; flag 0. |
| Flag 1, guardia manager forzata | Transizione rifiutata | Impostazioni restano correnti; flag resta 1. Dopo rimozione della guardia e **secondo evento imposto dal banco**, il descrittore sintetico diventa corrente e il flag passa a 0. |
| Flag 0 | Trampoline registra l'ID Nikon originale `0x87` | Impostazioni restano correnti perché il banco non esegue l'apertura originale. |

I tre casi sono **PASS** con stack conservato: [casi](../Risultati/GUI_S33/descriptor_settings_redirect_cpu_20261030T155111Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/descriptor_settings_redirect_cpu_20261030T155111Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/descriptor_settings_redirect_cpu_20261030T155111Z/fixture_patches.json). La modalità precedente senza `--redirect` è stata rieseguita: [due casi PASS](../Risultati/GUI_S33/descriptor_settings_back_request_cpu_20261030T155117Z/cases.json). I tentativi `155039Z` e `155057Z` sono FAIL esplorativi conservati; il secondo ha mostrato che le osservazioni del primo tentativo venivano sovrascritte dal retry, e la prova finale salva il flag prima di ripetere l'evento.

La prova suggerisce un contratto per la futura integrazione, non una patch installabile: il banco **impone** il flag, il contesto e il retry; il descrittore non ha risorse grafiche e non prova un menu funzionante. Il percorso Nikon senza flag è solo registrato, non eseguito, quindi la compatibilità con i ritorni originali non è dimostrata. Non sono verificati proprietà e ubicazione del flag, concorrenza, lifecycle, scheduler, tasti fisici, persistenza o display. DSP e servizi sono sperimentali o fixture; firmware originale, fotocamera e SD invariati. **NON_INSTALLARE**.
