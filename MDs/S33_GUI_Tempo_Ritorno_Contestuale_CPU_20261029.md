# Tempo: ritorno contestuale dopo conferma o annullo

Il 29 ottobre 2026 ho esteso la [prova del tempo](S33_GUI_Modello_Tempo_Conferma_Manager_CPU_20261029.md) con due trampoline sperimentali in una copia di laboratorio, uno nel percorso di conferma e uno in quello di annullo. Con flag sintetico 1, entrambi chiedono al manager di aprire il descrittore sintetico senza risorse `0x2050000`; cancellano il flag solo se la chiamata ritorna 1 e il descrittore corrente è quello richiesto. Con flag 0 mantengono il ritorno originale al menu diagnostico `0x987AF8`.

| Termine e condizione | Campi software | Descrittore finale / flag |
|---|---|---|
| Conferma, flag 0 | 121.000 / 121.000 | diagnostica / 0 |
| Conferma, flag 1 | 121.000 / 121.000 | sintetico / 0 |
| Annulla, flag 0 | sentinelle invariate | diagnostica / 0 |
| Annulla, flag 1 | sentinelle invariate | sintetico / 0 |
| Conferma, guardia manager forzata | 121.000 / 121.000 | tempo / 1 |
| Annulla, guardia manager forzata | sentinelle invariate | tempo / 1 |

Nei casi con guardia il manager rifiuta il ritorno e il flag rimane 1; **la conferma ha comunque già scritto i campi**. Non è stata verificata una riconferma successiva né l'idempotenza di altri effetti. I casi flag 0 conservano la destinazione originale nel perimetro provato.

[Sei casi PASS](../Risultati/GUI_S33/model_time_return_context_cpu_20261029T054129Z/verified_evidence.json), 65.680 istruzioni: modello, apertura diagnostica, incremento iniettato, campi, flag, descrittore e stack verificati. [Casi](../Risultati/GUI_S33/model_time_return_context_cpu_20261029T054129Z/cases.json), [traccia](../Risultati/GUI_S33/model_time_return_context_cpu_20261029T054129Z/cases.trace), [fixture e modifiche](../Risultati/GUI_S33/model_time_return_context_cpu_20261029T054129Z/fixture_patches.json), [banco](../Python_Trace_Scripts/s33_verify_gui_model_time_return_context_cpu.py).

Il flag è iniettato dal banco e non ha produttore o RAM fisica verificati; il descrittore è vuoto e il suo callback ritorna zero. Le modifiche sono solo nella copia sperimentale, non una patch installabile. Controlli, servizi e input sono sintetici, DSP sperimentale; non sono dimostrati unità del tempo, AE, scatto, tasti fisici, disegno o concorrenza. **NON_INSTALLARE**.
